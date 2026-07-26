FROM python:3.13.10-slim

WORKDIR /app

# Firefox runtime + Xvfb for Camoufox virtual display (headless='virtual' on Linux)
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget unzip ca-certificates curl \
    xvfb \
    libdbus-glib-1-2 libxt6 libx11-6 libxext6 \
    libnss3 libatk1.0-0 libatk-bridge2.0-0 libcups2 libdrm2 \
    libxkbcommon0 libxcomposite1 libxdamage1 libxfixes3 libxrandr2 \
    libgbm1 libasound2 libpangocairo-1.0-0 libpango-1.0-0 \
    libcairo2 libgtk-3-0 libx11-xcb1 libxcb-dri3-0 \
    fonts-liberation libappindicator3-1 xdg-utils \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt && \
    # Camoufox: download patched Firefox binary (v152, Linux)
    python -m camoufox fetch

COPY . .

# Camoufox uses headless='virtual' → auto-spawns Xvfb for WAF bypass
# fingerprint_preset, os spoofing, geoip, screen/window constraints
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
