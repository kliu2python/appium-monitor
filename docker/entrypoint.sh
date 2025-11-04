#!/usr/bin/env bash
set -euo pipefail

PORT_STRIDE=${PORT_STRIDE:-100}
if [[ -z "${PORT_OFFSET:-}" ]]; then
  host_name=$(cat /etc/hostname)
  if [[ $host_name =~ -([0-9]+)$ ]]; then
    idx=${BASH_REMATCH[1]}
  elif [[ $host_name =~ ([0-9]+)$ ]]; then
    idx=${BASH_REMATCH[1]}
  else
    idx=1
  fi
  if [[ $idx -gt 0 ]]; then
    export PORT_OFFSET=$(( (idx - 1) * PORT_STRIDE ))
  else
    export PORT_OFFSET=0
  fi
fi

export MONITOR_LOG_DIR=${MONITOR_LOG_DIR:-/data/logs}
export MONITOR_MAPPING_FILE=${MONITOR_MAPPING_FILE:-/data/mapping.json}
mkdir -p "${MONITOR_LOG_DIR}"
mkdir -p "$(dirname "${MONITOR_MAPPING_FILE}")"

if [[ ! -f "${MONITOR_MAPPING_FILE}" && -f /app/mapping.json ]]; then
  cp /app/mapping.json "${MONITOR_MAPPING_FILE}"
fi

exec "$@"
