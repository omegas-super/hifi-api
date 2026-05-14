FROM python:3.13.10-slim

WORKDIR /app

# System deps for camoufox (Firefox) and patchright (Chromium) shared libs
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget unzip ca-certificates curl \
    libnss3 libatk1.0-0 libatk-bridge2.0-0 libcups2 libdrm2 \
    libxkbcommon0 libxcomposite1 libxdamage1 libxfixes3 libxrandr2 \
    libgbm1 libasound2 libpangocairo-1.0-0 libpango-1.0-0 \
    libcairo2 libgtk-3-0 libx11-xcb1 libxcb-dri3-0 \
    fonts-liberation libappindicator3-1 xdg-utils \
    # Firefox runtime deps (for camoufox)
    libdbus-glib-1-2 libxt6 libx11-6 libxext6 \
    && rm -rf /var/lib/apt/lists/*

# Download fingerprint-chromium binary (Chrome 136 Linux build)
# Used as optional executablePath for patchright fallback
RUN mkdir -p /opt/fingerprint-chromium && \
    wget -q "https://github.com/adryfish/fingerprint-chromium/releases/download/136.0.7103.113/136.0.7103.113-1_linux.tar.xz" \
         -O /tmp/fp-chrome.tar.xz && \
    tar -xf /tmp/fp-chrome.tar.xz -C /opt/fingerprint-chromium --strip-components=1 && \
    rm /tmp/fp-chrome.tar.xz && \
    chmod +x /opt/fingerprint-chromium/chrome

ENV FINGERPRINT_CHROMIUM_PATH=/opt/fingerprint-chromium/chrome

COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt && \
    # camoufox: download patched Firefox binary (primary, true headless)
    python -m camoufox fetch && \
    # patchright: download patched Chromium (fallback, needs Xvfb)
    patchright install chromium --with-deps

COPY . .

# camoufox runs true headless — no DISPLAY / Xvfb needed
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
