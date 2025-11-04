# syntax=docker/dockerfile:1.4
FROM node:20-bullseye

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        python3 \
        python3-venv \
        python3-pip \
        android-tools-adb \
        usbmuxd \
        libimobiledevice6 \
        ideviceinstaller \
        iproxy \
        ca-certificates \
        git \
        unzip \
        curl \
        sudo \
    && rm -rf /var/lib/apt/lists/*

RUN npm install -g appium@2

WORKDIR /app

COPY appium_device_monitor.py mapping.json ./
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["python3", "/app/appium_device_monitor.py"]
