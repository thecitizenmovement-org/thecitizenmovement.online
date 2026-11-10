# Scam Intel API — Phase 1 backend (Render, free tier)
# Python 3.12 slim. Installs Python deps from requirements.txt, downloads
# PhoneInfoga v2.11.0 (same version as the local tools/phoneinfoga binary,
# verified by SHA256 — the binary itself is NOT committed to the repo, because
# the GitHub MCP push path cannot carry binary files correctly).
# Maigret comes from requirements.txt (maigret==0.6.6).
# The service is started with the uvicorn CLI (not `python app.py`), so it
# binds 0.0.0.0:$PORT as Render requires. app.py's __main__ block binds
# 127.0.0.1 only and is bypassed by the CLI start command.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# System tools needed at build time (curl for the PhoneInfoga download,
# ca-certificates for HTTPS). No compiler needed: all Python deps ship wheels.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Python dependencies first (better layer caching).
COPY requirements.txt ./
RUN pip install --upgrade pip \
    && pip install -r requirements.txt

# PhoneInfoga v2.11.0 — Linux x86_64, from the official release.
# SHA256 pinned from the v2.11.0 release (matches the local binary).
ARG PHONEINFOGA_VERSION=2.11.0
ARG PHONEINFOGA_SHA256=6173dfc4ec009a6fe688068bac5a250646f5a8f56409098f5edcc7e404b12a52
RUN mkdir -p /app/tools \
    && curl -sSL "https://github.com/sundowndev/phoneinfoga/releases/download/v${PHONEINFOGA_VERSION}/phoneinfoga_Linux_x86_64.tar.gz" -o /tmp/phoneinfoga.tar.gz \
    && echo "${PHONEINFOGA_SHA256}  /tmp/phoneinfoga.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/phoneinfoga.tar.gz -C /app/tools phoneinfoga \
    && chmod +x /app/tools/phoneinfoga \
    && rm /tmp/phoneinfoga.tar.gz \
    && /app/tools/phoneinfoga version

# Application code.
COPY app.py ./
COPY API_SPEC.md README.md ./

# Defaults (overridden by Render environment variables).
# PHONEINFOGA_BIN points at the binary downloaded above.
# MAIGRET_BIN is the `maigret` console script from the pip install.
ENV PHONEINFOGA_BIN=/app/tools/phoneinfoga \
    MAIGRET_BIN=maigret \
    MAIGRET_TOP_SITES=50 \
    MAIGRET_TIMEOUT=180 \
    PHONEINFOGA_TIMEOUT=90 \
    HTTP_TIMEOUT=15 \
    MAX_CONCURRENT_SCANS=3

# Render injects $PORT. Bind 0.0.0.0 so Render's router can reach us.
# SCAMINTEL_API_TOKEN, SUPABASE_URL and SUPABASE_SERVICE_KEY come from
# Render environment variables (never baked into the image).
CMD ["sh", "-c", "uvicorn app:app --host 0.0.0.0 --port ${PORT:-8000} --log-level info"]
