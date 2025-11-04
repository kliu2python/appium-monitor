#!/usr/bin/env python3
"""
Appium Device Monitor (Android + iOS) with HTTP API and Android/iOS MJPEG streaming (stdlib only).

- Android:
  * Watches `adb devices`
  * Assigns unique: appiumPort, systemPort, chromedriverPort
  * Optional per-device MJPEG stream (multipart) powered by `adb exec-out screencap -p`
- iOS:
  * Watches `idevice_id -l` (fallback to `ios list`)
  * Optional go-ios tunnel start
  * Mounts DDI, runs WDA (`ios runwda`)
  * Starts iproxy for WDA (8100->local wdaPort)
  * Appium per device, unique mjpeg/wda ports in caps

API endpoints:
  GET /healthz
  GET /devices
  GET /caps
  GET /caps/<deviceId>
  GET /count (or /counts)
  GET /stream/android/<serial>  -> single-port MJPEG stream (alt to per-device port)

Requirements:
  - adb, appium in PATH
  - For iOS: idevice_id (libimobiledevice), ios (go-ios), iproxy (libusbmuxd), usbmuxd
"""

import argparse
import json
import os
import signal
import socket
import subprocess
import sys
import time
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict, List, Set, Optional
from urllib.request import urlopen
from urllib.error import URLError

HERE = Path(__file__).resolve().parent
DEFAULT_LOG_DIR = Path(os.environ.get("MONITOR_LOG_DIR", str(HERE / "logs")))
DEFAULT_MAP_FILE = Path(os.environ.get("MONITOR_MAPPING_FILE", str(HERE / "mapping.json")))
LOG_DIR = DEFAULT_LOG_DIR
MAP_FILE = DEFAULT_MAP_FILE

STATE_LOCK = threading.Lock()
MAPPING: Dict[str, dict] = {}            # serial/udid -> ports/type
CAPS_SERVER: Dict[str, dict] = {}
CAPS_CLIENT_LOCAL: Dict[str, dict] = {}
CAPS_CLIENT_PUBLIC: Dict[str, dict] = {}

CURRENT_ANDROID: Set[str] = set()        # live sets for /count
CURRENT_IOS: Set[str] = set()

ANDROID_MJPEG_SERVERS: Dict[str, "ThreadingHTTPServer"] = {}
ANDROID_MJPEG_THREADS: Dict[str, threading.Thread] = {}
ANDROID_MJPEG_STOP: Dict[str, threading.Event] = {}

# ------------------------- utils -------------------------

def run(cmd: List[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

def popen(cmd: List[str], **kwargs) -> subprocess.Popen:
    if os.name == "posix" and "preexec_fn" not in kwargs:
        kwargs["preexec_fn"] = os.setsid
    return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, **kwargs)

def is_port_in_use(port: int, host: str = "127.0.0.1") -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.2)
        try:
            s.connect((host, port))
            return True
        except Exception:
            return False

def ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)

def log_path(name: str) -> Path:
    ensure_dir(LOG_DIR)
    return LOG_DIR / name

def first_non_loopback_ip() -> str:
    try:
        host = socket.gethostname()
        ips = socket.gethostbyname_ex(host)[2]
        for ip in ips:
            if not ip.startswith("127."):
                return ip
    except Exception:
        pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def appiumize_caps(raw: dict) -> dict:
    """Add 'appium:' prefix to non-W3C keys. Keep 'platformName'/'browserName' bare."""
    out = {}
    for k, v in (raw or {}).items():
        if k in ("platformName", "browserName") or k.startswith("appium:"):
            out[k] = v
        else:
            out[f"appium:{k}"] = v
    return out

# ------------------------- Android side -------------------------

def adb_devices() -> Dict[str, str]:
    try:
        out = run(["adb", "devices"]).stdout.strip().splitlines()
    except FileNotFoundError:
        print("[ERROR] `adb` not found in PATH.", flush=True)
        return {}
    devices = {}
    for line in out[1:]:
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) >= 2:
            serial, state = parts[0], parts[1]
            devices[serial] = state
    return devices

def ensure_adb_server():
    out = run(["adb", "start-server"])
    if out.returncode != 0:
        print("[ERROR] Failed to start adb server:\n", out.stderr, flush=True)

def adb_exec_screencap_png(serial: str, timeout_s: float = 2.5) -> Optional[bytes]:
    try:
        cp = subprocess.run(
            ["adb", "-s", serial, "exec-out", "screencap", "-p"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=timeout_s
        )
        if cp.returncode == 0 and cp.stdout:
            return cp.stdout  # PNG bytes
    except subprocess.TimeoutExpired:
        pass
    except Exception:
        pass
    return None

# ------------------------- iOS side -------------------------

def ios_udids(idevice_cmd: str, ios_bin: str) -> List[str]:
    udids: List[str] = []
    if idevice_cmd:
        try:
            cp = run([idevice_cmd, "-l"])
            if cp.returncode == 0:
                for line in (cp.stdout or "").splitlines():
                    s = line.strip()
                    if s:
                        udids.append(s)
        except FileNotFoundError:
            pass
    if udids:
        return udids
    try:
        cp = run([ios_bin, "list"])
        if cp.returncode == 0:
            try:
                doc = json.loads(cp.stdout or "{}")
                if isinstance(doc, dict):
                    lst = doc.get("deviceList") or doc.get("devices") or []
                    udids.extend([str(x) for x in lst if isinstance(x, (str, int))])
            except Exception:
                for line in (cp.stdout or "").splitlines():
                    try:
                        j = json.loads(line)
                        if isinstance(j, list):
                            udids.extend([str(x) for x in j if isinstance(x, (str, int))])
                    except Exception:
                        continue
    except FileNotFoundError:
        pass
    return udids

def ios_start_tunnel(ios_bin: str, mode: str = "user", use_sudo: bool = False) -> None:
    env = os.environ.copy()
    env["ENABLE_GO_IOS_AGENT"] = mode
    cmd = [ios_bin, "tunnel", "start"]
    if use_sudo:
        cmd = ["sudo", "-E", "-b"] + cmd
    try:
        popen(cmd, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.8)
    except Exception as e:
        print(f"[WARN] ios tunnel start failed: {e}", flush=True)

def ios_image_auto(ios_bin: str, udid: str) -> None:
    try:
        cp = run([ios_bin, "image", "auto", f"--udid={udid}", "--nojson"])
        if cp.returncode != 0:
            print(f"[WARN] DDI mount failed for {udid}: {cp.stderr.strip()}", flush=True)
    except Exception as e:
        print(f"[WARN] DDI mount exception for {udid}: {e}", flush=True)

def ios_run_wda(ios_bin: str, udid: str, bid: str, wda_log: Path) -> subprocess.Popen:
    logf = wda_log.open("a", buffering=1)
    cmd = [
        ios_bin, "runwda",
        f"--udid={udid}",
        f"--bundleid={bid}",
        f"--testrunnerbundleid={bid}",
        "--xctestconfig=WebDriverAgentRunner.xctest",
        "--nojson"
    ]
    print(f"[INFO] WDA start {udid}: {' '.join(cmd)}", flush=True)
    if os.name == "posix":
        return subprocess.Popen(cmd, stdout=logf, stderr=logf, text=True, preexec_fn=os.setsid)
    else:
        return subprocess.Popen(cmd, stdout=logf, stderr=logf, text=True)

def start_iproxy(iproxy_cmd: str, udid: str, local_port: int, remote_port: int = 8100) -> subprocess.Popen:
    logf = log_path(f"iproxy-{udid}-{local_port}.log").open("a", buffering=1)
    cmd = [iproxy_cmd, str(local_port), str(remote_port), "-u", udid]
    print(f"[INFO] iproxy {udid}: 127.0.0.1:{local_port} -> {udid}:{remote_port}", flush=True)
    if os.name == "posix":
        return subprocess.Popen(cmd, stdout=logf, stderr=logf, text=True, preexec_fn=os.setsid)
    else:
        return subprocess.Popen(cmd, stdout=logf, stderr=logf, text=True)

# ------------------------- Appium per device -------------------------

def start_appium_for_device(
    serial: str,
    port: int,
    address: str,
    base_path: str,
    relaxed_security: bool,
    default_caps: dict,
    appium_cmd: str,
) -> subprocess.Popen:
    ensure_dir(LOG_DIR)
    log_file = log_path(f"appium-{serial}-{port}.log").open("a", buffering=1)

    caps = dict(default_caps) if default_caps else {}
    caps.setdefault("newCommandTimeout", 0)
    caps["udid"] = serial

    cmd = [
        appium_cmd,
        "--base-path", base_path,
        "-p", str(port),
        "--address", address,
        "--default-capabilities", json.dumps(caps),
    ]
    if relaxed_security:
        cmd.insert(1, "--relaxed-security")

    print(f"[INFO] Starting Appium for {serial} on {address}:{port}", flush=True)
    print(f"[INFO]   Command: {' '.join(cmd)}", flush=True)

    if os.name == "posix":
        return subprocess.Popen(cmd, stdout=log_file, stderr=log_file, text=True, preexec_fn=os.setsid)
    else:
        return subprocess.Popen(cmd, stdout=log_file, stderr=log_file, text=True)

def stop_proc_tree(proc: subprocess.Popen, name: str, timeout: float = 5.0):
    try:
        if proc.poll() is not None:
            return
        print(f"[INFO] Stopping {name} (pid={proc.pid}) ...", flush=True)
        if os.name == "posix":
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        else:
            proc.terminate()
        t0 = time.time()
        while proc.poll() is None and (time.time() - t0) < timeout:
            time.sleep(0.2)
        if proc.poll() is None:
            print(f"[WARN] Forcing kill for {name}", flush=True)
            if os.name == "posix":
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            else:
                proc.kill()
    except Exception as e:
        print(f"[WARN] Failed to stop {name}: {e}", flush=True)

# ------------------------- mapping -------------------------

def load_mapping() -> Dict[str, dict]:
    if MAP_FILE.exists():
        try:
            raw = json.loads(MAP_FILE.read_text())
            if raw and all(isinstance(v, int) for v in raw.values()):
                # migrate old simple {serial: appiumPort}
                return {k: {"type": "android", "appiumPort": v} for k, v in raw.items()}
            return raw
        except Exception:
            return {}
    return {}

def save_mapping(mapping: Dict[str, dict]) -> None:
    try:
        MAP_FILE.write_text(json.dumps(mapping, indent=2, sort_keys=True))
    except Exception as e:
        print(f"[WARN] Failed to persist mapping: {e}", flush=True)

def next_free_port(base_port: int, used_ports: Set[int]) -> int:
    port = base_port
    while port in used_ports:
        port += 1
    return port

# ------------------------- Android MJPEG server -------------------------

class AndroidMjpegHandler(BaseHTTPRequestHandler):
    """Per-device MJPEG-like streaming: multipart frames from adb screencap (PNG)."""
    server_serial: str = ""
    fps: float = 2.0
    stop_event: threading.Event

    def _send_headers(self):
        self.send_response(200)
        self.send_header("Content-Type", "multipart/x-mixed-replace; boundary=frame")
        self.end_headers()

    def log_message(self, fmt, *args):
        return

    def do_GET(self):
        if self.path not in ("/", "/stream"):
            self.send_response(404)
            self.end_headers()
            return
        serial = getattr(self.server, "server_serial", "")
        stop_ev: threading.Event = getattr(self.server, "stop_event")
        fps = float(getattr(self.server, "fps", 2.0))
        delay = max(0.05, 1.0 / max(0.1, fps))

        try:
            self._send_headers()
            while not stop_ev.is_set():
                frame = adb_exec_screencap_png(serial, timeout_s=2.5)
                if not frame:
                    time.sleep(0.25)
                    continue
                try:
                    self.wfile.write(b"--frame\r\n")
                    self.wfile.write(b"Content-Type: image/png\r\n")
                    self.wfile.write(f"Content-Length: {len(frame)}\r\n\r\n".encode("ascii"))
                    self.wfile.write(frame)
                    self.wfile.write(b"\r\n")
                    self.wfile.flush()
                except BrokenPipeError:
                    break
                time.sleep(delay)
        except Exception:
            pass

def start_android_mjpeg_server(serial: str, port: int, fps: float = 2.0) -> ThreadingHTTPServer:
    handler_cls = AndroidMjpegHandler
    srv = ThreadingHTTPServer(("0.0.0.0", port), handler_cls)
    srv.server_serial = serial      # type: ignore[attr-defined]
    srv.fps = fps                   # type: ignore[attr-defined]
    srv.stop_event = threading.Event()  # type: ignore[attr-defined]
    t = threading.Thread(target=srv.serve_forever, name=f"mjpg-{serial}", daemon=True)
    t.start()
    ANDROID_MJPEG_SERVERS[serial] = srv
    ANDROID_MJPEG_THREADS[serial] = t
    ANDROID_MJPEG_STOP[serial] = srv.stop_event
    print(f"[INFO] Android MJPEG for {serial} on 0.0.0.0:{port} (/{'stream'})", flush=True)
    return srv

def stop_android_mjpeg_server(serial: str):
    srv = ANDROID_MJPEG_SERVERS.pop(serial, None)
    if not srv:
        return
    stop_ev = ANDROID_MJPEG_STOP.pop(serial, None)
    if stop_ev:
        stop_ev.set()
    try:
        srv.shutdown()
    except Exception:
        pass
    t = ANDROID_MJPEG_THREADS.pop(serial, None)
    if t:
        t.join(timeout=1.0)

# ------------------------- API server -------------------------

class ApiHandler(BaseHTTPRequestHandler):
    server_cfg = {
        "base_path": "/wd/hub",
        "address": "0.0.0.0",
        "public_host": "127.0.0.1",
        "api_port": 8099
    }

    def _send_json(self, obj, code=200):
        body = json.dumps(obj, indent=2, sort_keys=True)
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body.encode("utf-8"))))
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))

    def log_message(self, fmt, *args):
        return

    def do_GET(self):
        try:
            if self.path == "/healthz":
                return self._send_json({"ok": True})

            if self.path in ("/count", "/counts"):
                with STATE_LOCK:
                    total_active = len(CURRENT_ANDROID) + len(CURRENT_IOS)
                    resp = {
                        "total": total_active,
                        "android": len(CURRENT_ANDROID),
                        "ios": len(CURRENT_IOS),
                        "known": {
                            "total": len(MAPPING),
                            "android": sum(1 for v in MAPPING.values() if v.get("type") == "android"),
                            "ios": sum(1 for v in MAPPING.values() if v.get("type") == "ios"),
                        },
                    }
                return self._send_json(resp)

            if self.path.startswith("/stream/android/"):
                serial = self.path.rsplit("/", 1)[-1]
                # Serve a single client stream from the main API port
                # (This is separate from per-device port servers.)
                return self._serve_android_stream_inline(serial)

            if self.path == "/devices":
                with STATE_LOCK:
                    payload = {}
                    for k, v in MAPPING.items():
                        info = dict(v)
                        ap_port = info.get("appiumPort")
                        if ap_port:
                            info["appiumUrlLocal"]  = f"http://127.0.0.1:{ap_port}{self.server_cfg['base_path']}"
                            info["appiumUrlPublic"] = f"http://{self.server_cfg['public_host']}:{ap_port}{self.server_cfg['base_path']}"
                        if info.get("type") == "ios":
                            w = info.get("wdaPort")
                            if w:
                                info["wdaUrls"] = {
                                    "local": f"http://127.0.0.1:{w}",
                                    "public": f"http://self.server_cfg['public_host']:{w}".replace("self.server_cfg['public_host']", self.server_cfg['public_host']),
                                }
                        if info.get("type") == "android":
                            mj = info.get("androidMjpegPort")
                            if mj:
                                info["mjpegUrls"] = {
                                    "local":  f"http://127.0.0.1:{mj}/",
                                    "public": f"http://{self.server_cfg['public_host']}:{mj}/",
                                }
                        payload[k] = info
                return self._send_json(payload)

            if self.path.startswith("/caps"):
                parts = self.path.strip("/").split("/", 2)
                device = parts[1] if len(parts) > 1 else None
                with STATE_LOCK:
                    if device:
                        if device not in MAPPING:
                            return self._send_json({"error": "device not found"}, 404)
                        data = {
                            "device": device,
                            "type": MAPPING[device].get("type"),
                            "serverDefaultCaps": CAPS_SERVER.get(device, {}),
                            "clientCapsLocal":  CAPS_CLIENT_LOCAL.get(device, {}),
                            "clientCapsPublic": CAPS_CLIENT_PUBLIC.get(device, {}),
                        }
                        return self._send_json(data)
                    else:
                        out = {}
                        for d in MAPPING.keys():
                            out[d] = {
                                "type": MAPPING[d].get("type"),
                                "serverDefaultCaps": CAPS_SERVER.get(d, {}),
                                "clientCapsLocal":  CAPS_CLIENT_LOCAL.get(d, {}),
                                "clientCapsPublic": CAPS_CLIENT_PUBLIC.get(d, {}),
                            }
                        return self._send_json(out)

            return self._send_json({"error": "not found"}, 404)
        except Exception as e:
            return self._send_json({"error": str(e)}, 500)

    def _serve_android_stream_inline(self, serial: str):
        # inline streaming on API port (alternative to per-device port)
        if serial not in CURRENT_ANDROID:
            self.send_response(404); self.end_headers(); return
        try:
            self.send_response(200)
            self.send_header("Content-Type", "multipart/x-mixed-replace; boundary=frame")
            self.end_headers()
            while True:
                frame = adb_exec_screencap_png(serial, timeout_s=2.5)
                if not frame:
                    time.sleep(0.25); continue
                try:
                    self.wfile.write(b"--frame\r\n")
                    self.wfile.write(b"Content-Type: image/png\r\n")
                    self.wfile.write(f"Content-Length: {len(frame)}\r\n\r\n".encode("ascii"))
                    self.wfile.write(frame)
                    self.wfile.write(b"\r\n")
                    self.wfile.flush()
                except BrokenPipeError:
                    break
                time.sleep(0.5)  # ~2 fps
        except Exception:
            pass

def start_api(host: str, port: int, base_path: str, public_host: str) -> ThreadingHTTPServer:
    ApiHandler.server_cfg = {
        "base_path": base_path,
        "address": host,
        "public_host": public_host,
        "api_port": port,
    }
    httpd = ThreadingHTTPServer((host, port), ApiHandler)
    t = threading.Thread(target=httpd.serve_forever, name="api-server", daemon=True)
    t.start()
    print(f"[INFO] API listening on http://{host}:{port}", flush=True)
    return httpd

# ------------------------- main -------------------------

def main():
    global LOG_DIR, MAP_FILE
    ap = argparse.ArgumentParser(description="Monitor Android & iOS devices and run one Appium per device (with API & MJPEG).")
    # Common / Appium
    ap.add_argument("--base-port", type=int, default=4723, help="Starting Appium port (default: 4723)")
    ap.add_argument("--address", type=str, default="0.0.0.0", help="Appium bind address (default: 0.0.0.0)")
    ap.add_argument("--base-path", type=str, default="/wd/hub", help="Appium base path (default: /wd/hub)")
    ap.add_argument("--poll-interval", type=float, default=5.0, help="Polling interval seconds (default: 5)")
    ap.add_argument("--appium-cmd", type=str, default="appium", help="Appium executable (default: appium)")
    ap.add_argument("--no-relaxed-security", action="store_true", help="Disable --relaxed-security")
    ap.add_argument("--default-caps-android", type=str,
                    default='{"platformName":"Android","automationName":"UiAutomator2"}',
                    help='JSON for default Android caps')
    ap.add_argument("--default-caps-ios", type=str,
                    default='{"platformName":"iOS","automationName":"XCUITest"}',
                    help='JSON for default iOS caps')

    # Toggles
    ap.add_argument("--monitor-android", action="store_true", default=True, help="Monitor Android (default on)")
    ap.add_argument("--monitor-ios", action="store_true", default=True, help="Monitor iOS (default on)")

    # Android specifics
    ap.add_argument("--android-system-port-base", type=int, default=8200)
    ap.add_argument("--android-chromedriver-port-base", type=int, default=9515)
    ap.add_argument("--android-mjpg-base-port", type=int, default=9700,
                    help="Starting MJPEG stream port per Android device")
    ap.add_argument("--android-mjpg-fps", type=float, default=2.0,
                    help="Android MJPEG FPS (approx)")

    # iOS specifics
    ap.add_argument("--ios-bid", type=str, default="com.facebook.WebDriverAgentRunner.xctrunner")
    ap.add_argument("--ios-bin", type=str, default="/usr/bin/ios")
    ap.add_argument("--iproxy-cmd", type=str, default="iproxy")
    ap.add_argument("--idevice-cmd", type=str, default="idevice_id")

    ap.add_argument("--ios-wda-base-port", type=int, default=8100)
    ap.add_argument("--ios-mjpg-base-port", type=int, default=9100)
    ap.add_argument("--ios-tunnel", action="store_true")
    ap.add_argument("--ios-tunnel-mode", type=str, default="user", choices=["user", "kernel"])
    ap.add_argument("--ios-tunnel-sudo", action="store_true")

    # iOS extra caps knobs
    ap.add_argument("--ios-start-iwdp", action="store_true")
    ap.add_argument("--no-reset", dest="no_reset", action="store_true", default=True)
    ap.add_argument("--reset", dest="no_reset", action="store_false")
    ap.add_argument("--new-command-timeout", type=int, default=3600)

    # API
    ap.add_argument("--api", action="store_true", default=True)
    ap.add_argument("--api-host", type=str, default="0.0.0.0")
    ap.add_argument("--api-port", type=int, default=8099)
    ap.add_argument("--public-host", type=str, default="")

    # Container / multi-replica helpers
    ap.add_argument("--log-dir", type=str, default=str(LOG_DIR),
                    help="Directory for logs (default: MONITOR_LOG_DIR or ./logs)")
    ap.add_argument("--mapping-file", type=str, default=str(MAP_FILE),
                    help="Path to mapping file (default: MONITOR_MAPPING_FILE or ./mapping.json)")
    ap.add_argument("--port-offset", type=int, default=int(os.environ.get("PORT_OFFSET", "0")),
                    help="Additive offset applied to all base ports (env: PORT_OFFSET)")

    args = ap.parse_args()
    relaxed_security = not args.no_relaxed_security

    LOG_DIR = Path(args.log_dir).expanduser()
    MAP_FILE = Path(args.mapping_file).expanduser()

    if args.port_offset:
        args.base_port += args.port_offset
        args.api_port += args.port_offset
        args.android_system_port_base += args.port_offset
        args.android_chromedriver_port_base += args.port_offset
        args.android_mjpg_base_port += args.port_offset
        args.ios_wda_base_port += args.port_offset
        args.ios_mjpg_base_port += args.port_offset

    # caps defaults
    try:
        default_caps_android = json.loads(args.default_caps_android) if args.default_caps_android else {}
    except Exception as e:
        print(f"[WARN] Ignoring invalid --default-caps-android: {e}", flush=True)
        default_caps_android = {"platformName": "Android", "automationName": "UiAutomator2"}

    try:
        default_caps_ios_user = json.loads(args.default_caps_ios) if args.default_caps_ios else {}
    except Exception as e:
        print(f"[WARN] Ignoring invalid --default-caps-ios: {e}", flush=True)
        default_caps_ios_user = {"platformName": "iOS", "automationName": "XCUITest"}

    ensure_dir(LOG_DIR)

    global MAPPING, CAPS_SERVER, CAPS_CLIENT_LOCAL, CAPS_CLIENT_PUBLIC
    MAPPING = load_mapping()
    CAPS_SERVER = {}
    CAPS_CLIENT_LOCAL = {}
    CAPS_CLIENT_PUBLIC = {}

    public_host = args.public_host or first_non_loopback_ip()

    # API bg
    httpd = None
    if args.api:
        httpd = start_api(args.api_host, args.api_port, args.base_path, public_host)

    print("[INFO] Appium Device Monitor started.", flush=True)
    print(f"[INFO] Appium base port: {args.base_port}, iOS WDA base: {args.ios_wda_base_port}, iOS MJPEG base: {args.ios_mjpg_base_port}, ANDR MJPEG base: {args.android_mjpg_base_port}", flush=True)
    print(f"[INFO] API at http://{args.api_host}:{args.api_port} (public host: {public_host})", flush=True)

    if args.monitor_ios and args.ios_tunnel:
        ios_start_tunnel(args.ios_bin, mode=args.ios_tunnel_mode, use_sudo=args.ios_tunnel_sudo)
    if args.monitor_android:
        ensure_adb_server()

    appium_procs: Dict[str, subprocess.Popen] = {}
    wda_procs: Dict[str, subprocess.Popen] = {}
    iproxy_procs: Dict[str, subprocess.Popen] = {}

    try:
        while True:
            android_devices = adb_devices() if args.monitor_android else {}
            android_serials = [s for s, st in android_devices.items() if st == "device"]
            for s, st in android_devices.items():
                if st != "device":
                    print(f"[WARN] ANDR: skipping {s} (state={st})", flush=True)

            ios_devices = ios_udids(args.idevice_cmd, args.ios_bin) if args.monitor_ios else []

            # snapshot for /count
            with STATE_LOCK:
                global CURRENT_ANDROID, CURRENT_IOS
                CURRENT_ANDROID = set(android_serials)
                CURRENT_IOS = set(ios_devices)

            # port pools
            with STATE_LOCK:
                used_appium_ports: Set[int] = {v.get("appiumPort") for v in MAPPING.values() if isinstance(v, dict) and v.get("appiumPort")}
                used_wda_ports: Set[int] = {v.get("wdaPort") for v in MAPPING.values() if isinstance(v, dict) and v.get("wdaPort")}
                used_mjpg_ports_ios: Set[int] = {v.get("mjpgPort") for v in MAPPING.values() if isinstance(v, dict) and v.get("mjpgPort")}
                used_sys_ports: Set[int] = {v.get("systemPort") for v in MAPPING.values() if isinstance(v, dict) and v.get("systemPort")}
                used_cdp_ports: Set[int] = {v.get("chromedriverPort") for v in MAPPING.values() if isinstance(v, dict) and v.get("chromedriverPort")}
                used_mjpg_ports_and: Set[int] = {v.get("androidMjpegPort") for v in MAPPING.values() if isinstance(v, dict) and v.get("androidMjpegPort")}

                # new Android
                for serial in android_serials:
                    if serial not in MAPPING:
                        ap_port = next_free_port(args.base_port, used_appium_ports)
                        sys_port = next_free_port(args.android_system_port_base, used_sys_ports or set())
                        cdp_port = next_free_port(args.android_chromedriver_port_base, used_cdp_ports or set())
                        and_mjpg = next_free_port(args.android_mjpg_base_port, used_mjpg_ports_and or set())
                        MAPPING[serial] = {
                            "type": "android",
                            "appiumPort": ap_port,
                            "systemPort": sys_port,
                            "chromedriverPort": cdp_port,
                            "androidMjpegPort": and_mjpg
                        }
                        used_appium_ports.add(ap_port)
                        (used_sys_ports or set()).add(sys_port)
                        (used_cdp_ports or set()).add(cdp_port)
                        (used_mjpg_ports_and or set()).add(and_mjpg)
                        save_mapping(MAPPING)

                # new iOS
                for udid in ios_devices:
                    if udid not in MAPPING:
                        ap_port = next_free_port(args.base_port, used_appium_ports)
                        wda_port = next_free_port(args.ios_wda_base_port, used_wda_ports)
                        mjpg_port = next_free_port(args.ios_mjpg_base_port, used_mjpg_ports_ios)
                        MAPPING[udid] = {
                            "type": "ios",
                            "appiumPort": ap_port,
                            "wdaPort": wda_port,
                            "mjpgPort": mjpg_port
                        }
                        used_appium_ports.add(ap_port)
                        used_wda_ports.add(wda_port)
                        used_mjpg_ports_ios.add(mjpg_port)
                        save_mapping(MAPPING)

            # ANDROID: start servers & mjpeg
            for serial in android_serials:
                info = MAPPING.get(serial, {}) or {}
                if info.get("type") != "android":
                    with STATE_LOCK:
                        ap_port = next_free_port(args.base_port, {v.get("appiumPort") for v in MAPPING.values() if isinstance(v, dict)})
                        info = {"type": "android", "appiumPort": ap_port}
                        MAPPING[serial] = info; save_mapping(MAPPING)

                ap_port = int(info["appiumPort"])
                sys_port = int(info.get("systemPort", next_free_port(args.android_system_port_base, set())))
                cdp_port = int(info.get("chromedriverPort", next_free_port(args.android_chromedriver_port_base, set())))
                and_mjpg = int(info.get("androidMjpegPort", next_free_port(args.android_mjpg_base_port, set())))

                # Start per-device MJPEG server if not running
                if serial not in ANDROID_MJPEG_SERVERS:
                    try:
                        start_android_mjpeg_server(serial, and_mjpg, fps=args.android_mjpg_fps)
                    except OSError as e:
                        print(f"[WARN] Could not start Android MJPEG on {and_mjpg} for {serial}: {e}", flush=True)

                # Start Appium per Android
                if serial not in appium_procs or appium_procs[serial].poll() is not None:
                    # build caps
                    android_caps = dict(default_caps_android) if default_caps_android else {}
                    android_caps.setdefault("platformName", "Android")
                    android_caps.setdefault("automationName", "UiAutomator2")
                    android_caps.setdefault("newCommandTimeout", 0)
                    android_caps.setdefault("deviceName", serial)
                    android_caps["udid"] = serial
                    android_caps["systemPort"] = sys_port
                    android_caps["chromedriverPort"] = cdp_port
                    # Convenience: report MJPEG port in caps (Appium will ignore on Android)
                    android_caps["mjpegServerPort"] = and_mjpg

                    # clear stale forwards (avoid "more than one device/emulator" on 8200)
                    run(["adb", "-s", serial, "forward", "--remove-all"])

                    if is_port_in_use(ap_port):
                        print(f"[WARN] ANDR: port {ap_port} in use. Assuming Appium already running for {serial}.", flush=True)
                    else:
                        proc = start_appium_for_device(
                            serial=serial,
                            port=ap_port,
                            address=args.address,
                            base_path=args.base_path,
                            relaxed_security=relaxed_security,
                            default_caps=android_caps,
                            appium_cmd=args.appium_cmd,
                        )
                        appium_procs[serial] = proc

                # Update /caps (Android)
                with STATE_LOCK:
                    appium_url_local  = f"http://127.0.0.1:{ap_port}{args.base_path}"
                    appium_url_public = f"http://{public_host}:{ap_port}{args.base_path}"
                    mj_local  = f"http://127.0.0.1:{and_mjpg}/"
                    mj_public = f"http://{public_host}:{and_mjpg}/"

                    server_caps_raw = {
                        "platformName": "Android",
                        "automationName": default_caps_android.get("automationName", "UiAutomator2"),
                        "udid": serial,
                        "systemPort": sys_port,
                        "chromedriverPort": cdp_port,
                        "mjpegServerPort": and_mjpg,   # FYI only
                    }
                    server_api = appiumize_caps(server_caps_raw)
                    server_api["appium:appiumUrlLocal"]  = appium_url_local
                    server_api["appium:appiumUrlPublic"] = appium_url_public
                    server_api["appium:mjpgPort"]        = and_mjpg
                    server_api["appium:mjpegUrls"]       = {"local": mj_local, "public": mj_public}
                    CAPS_SERVER[serial] = server_api

                    client_base = {
                        "platformName": "Android",
                        "automationName": server_caps_raw["automationName"],
                        "udid": serial,
                        "systemPort": sys_port,
                        "chromedriverPort": cdp_port,
                        # viewer hints:
                        "mjpegServerPort": and_mjpg,
                        "appiumUrlLocal": appium_url_local,
                        "appiumUrlPublic": appium_url_public,
                        "mjpegUrls": {"local": mj_local, "public": mj_public},
                    }
                    CAPS_CLIENT_LOCAL[serial]  = appiumize_caps(client_base)
                    CAPS_CLIENT_PUBLIC[serial] = appiumize_caps(client_base)

            # IOS: start WDA + iproxy + Appium
            for udid in ios_devices:
                info = MAPPING.get(udid, {}) or {}
                if info.get("type") != "ios":
                    with STATE_LOCK:
                        ap_port = next_free_port(args.base_port, {v.get("appiumPort") for v in MAPPING.values() if isinstance(v, dict)})
                        wda_port = next_free_port(args.ios_wda_base_port, {v.get("wdaPort") for v in MAPPING.values() if isinstance(v, dict)})
                        mjpg_port = next_free_port(args.ios_mjpg_base_port, {v.get("mjpgPort") for v in MAPPING.values() if isinstance(v, dict)})
                        info = {"type": "ios", "appiumPort": ap_port, "wdaPort": wda_port, "mjpgPort": mjpg_port}
                        MAPPING[udid] = info; save_mapping(MAPPING)

                ap_port = int(info["appiumPort"]); wda_port = int(info["wdaPort"]); mjpg_port = int(info["mjpgPort"])

                # WDA
                if udid not in wda_procs or wda_procs[udid].poll() is not None:
                    ios_image_auto(args.ios_bin, udid)
                    wda_procs[udid] = ios_run_wda(args.ios_bin, udid, args.ios_bid, log_path(f"wda-{udid}.log"))
                    time.sleep(0.5)
                # iproxy
                if udid not in iproxy_procs or iproxy_procs[udid].poll() is not None:
                    iproxy_procs[udid] = start_iproxy(args.iproxy_cmd, udid, wda_port, 8100)
                    time.sleep(0.3)

                # Appium for iOS
                if udid not in appium_procs or appium_procs[udid].poll() is not None:
                    ios_caps = dict(default_caps_ios_user) if default_caps_ios_user else {}
                    ios_caps.setdefault("platformName", "iOS")
                    ios_caps.setdefault("automationName", "XCUITest")
                    ios_caps.setdefault("usePrebuiltWDA", True)
                    ios_caps.setdefault("useNewWDA", False)
                    ios_caps["udid"] = udid
                    ios_caps["wdaLocalPort"] = wda_port
                    ios_caps["mjpegServerPort"] = mjpg_port
                    ios_caps["webDriverAgentUrl"] = f"http://127.0.0.1:{wda_port}"
                    if args.ios_start_iwdp:
                        ios_caps["startIWDP"] = True
                    ios_caps["noReset"] = True if args.no_reset else False
                    ios_caps["newCommandTimeout"] = int(args.new_command_timeout)

                    if is_port_in_use(ap_port):
                        print(f"[WARN]  iOS: port {ap_port} in use. Assuming Appium already running for {udid}.", flush=True)
                    else:
                        proc = start_appium_for_device(
                            serial=udid,
                            port=ap_port,
                            address=args.address,
                            base_path=args.base_path,
                            relaxed_security=relaxed_security,
                            default_caps=ios_caps,
                            appium_cmd=args.appium_cmd,
                        )
                        appium_procs[udid] = proc

                # Update /caps (iOS)
                with STATE_LOCK:
                    appium_url_local  = f"http://127.0.0.1:{ap_port}{args.base_path}"
                    appium_url_public = f"http://{public_host}:{ap_port}{args.base_path}"
                    wda_urls = {"local": f"http://127.0.0.1:{wda_port}", "public": f"http://{public_host}:{wda_port}"}

                    server_caps_raw = {
                        "platformName": "iOS",
                        "automationName": default_caps_ios_user.get("automationName", "XCUITest"),
                        "udid": udid,
                        "wdaLocalPort": wda_port,
                        "mjpegServerPort": mjpg_port,
                        "usePrebuiltWDA": True,
                        "useNewWDA": False,
                        "webDriverAgentUrl": f"http://127.0.0.1:{wda_port}",
                        "startIWDP": True if args.ios_start_iwdp else False,
                        "noReset": True if args.no_reset else False,
                        "newCommandTimeout": int(args.new_command_timeout),
                    }
                    server_api = appiumize_caps(server_caps_raw)
                    server_api["appium:appiumUrlLocal"]  = appium_url_local
                    server_api["appium:appiumUrlPublic"] = appium_url_public
                    server_api["appium:wdaPort"]         = wda_port
                    server_api["appium:mjpgPort"]        = mjpg_port
                    server_api["appium:wdaUrls"]         = wda_urls
                    CAPS_SERVER[udid] = server_api

                    client_local_raw = {
                        "platformName": "iOS",
                        "automationName": server_caps_raw["automationName"],
                        "udid": udid,
                        "webDriverAgentUrl": f"http://127.0.0.1:{wda_port}",
                        "mjpegServerPort": mjpg_port,
                        "usePrebuiltWDA": True,
                        "useNewWDA": False,
                        "startIWDP": server_caps_raw["startIWDP"],
                        "noReset": server_caps_raw["noReset"],
                        "newCommandTimeout": server_caps_raw["newCommandTimeout"],
                        "appiumUrlLocal": appium_url_local,
                        "appiumUrlPublic": appium_url_public,
                        "wdaPort": wda_port,
                        "wdaUrls": wda_urls,
                    }
                    client_local_api = appiumize_caps(client_local_raw)

                    client_public_raw = dict(client_local_raw)
                    client_public_raw["webDriverAgentUrl"] = f"http://{public_host}:{wda_port}"
                    client_public_api = appiumize_caps(client_public_raw)

                    CAPS_CLIENT_LOCAL[udid]  = client_local_api
                    CAPS_CLIENT_PUBLIC[udid] = client_public_api

            # Cleanup for disappeared devices
            live_android = set(android_serials)
            live_ios = set(ios_devices)
            live_all = live_android.union(live_ios)

            for dev, proc in list(appium_procs.items()):
                if dev not in live_all:
                    stop_proc_tree(proc, name=f"Appium({dev})")
                    del appium_procs[dev]
                    with STATE_LOCK:
                        CAPS_SERVER.pop(dev, None)
                        CAPS_CLIENT_LOCAL.pop(dev, None)
                        CAPS_CLIENT_PUBLIC.pop(dev, None)

            for udid, proc in list(wda_procs.items()):
                if udid not in live_ios:
                    stop_proc_tree(proc, name=f"WDA({udid})")
                    del wda_procs[udid]

            for udid, proc in list(iproxy_procs.items()):
                if udid not in live_ios:
                    stop_proc_tree(proc, name=f"iproxy({udid})")
                    del iproxy_procs[udid]

            for serial in list(ANDROID_MJPEG_SERVERS.keys()):
                if serial not in live_android:
                    stop_android_mjpeg_server(serial)

            # status line
            with STATE_LOCK:
                a_status = ", ".join(
                    f"{s}:appium{MAPPING[s]['appiumPort']}/sys{MAPPING[s].get('systemPort')}/cdp{MAPPING[s].get('chromedriverPort')}/mjpg{MAPPING[s].get('androidMjpegPort')}"
                    for s in live_android if s in MAPPING and MAPPING[s].get("type") == "android"
                ) or "none"
                i_status = ", ".join(
                    f"{u}:appium{MAPPING[u]['appiumPort']}/wda{MAPPING[u]['wdaPort']}/mjpg{MAPPING[u]['mjpgPort']}"
                    for u in live_ios if u in MAPPING and MAPPING[u].get("type") == "ios"
                ) or "none"
            print(f"[INFO] ANDR({len(live_android)}): {a_status} | iOS({len(live_ios)}): {i_status}", flush=True)

            time.sleep(args.poll_interval)

    except KeyboardInterrupt:
        print("\n[INFO] Shutting down ...", flush=True)
    finally:
        for proc in list(appium_procs.values()):
            stop_proc_tree(proc, name="Appium")
        for proc in list(iproxy_procs.values()):
            stop_proc_tree(proc, name="iproxy")
        for proc in list(wda_procs.values()):
            stop_proc_tree(proc, name="WDA")
        for serial in list(ANDROID_MJPEG_SERVERS.keys()):
            stop_android_mjpeg_server(serial)
        if httpd:
            httpd.shutdown()
        print("[INFO] Done.", flush=True)

if __name__ == "__main__":
    main()
