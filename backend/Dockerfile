# Scam Intel API — Phase 1 backend (Render, free tier)
# Python 3.12 slim. Installs Python deps from requirements.txt, downloads
# PhoneInfoga v2.11.0 and subfinder v2.17.0 (same versions as the local
# tools/ binaries, verified by SHA256 — the binaries themselves are NOT
# committed to the repo, because the GitHub MCP push path cannot carry
# binary files correctly).
# Maigret and user-scanner come from requirements.txt.
# theHarvester is NOT installed (blocked — see app.py docstring).
# The service is started with the uvicorn CLI (not `python app.py`), so it
# binds 0.0.0.0:$PORT as Render requires. app.py's __main__ block binds
# 127.0.0.1 only and is bypassed by the CLI start command.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# System tools needed at build time (curl for the binary downloads,
# ca-certificates for HTTPS, unzip for the subfinder zip). No compiler
# needed: all Python deps ship wheels.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates unzip \
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

# subfinder v2.17.0 — Linux x86_64, from the official release.
# SHA256 pinned from the v2.17.0 release checksums file (verified Nov 10,
# 2026: a39c3e5c7a26ef3c430915c4d6cbf7716a00f26769a75e9405aba796142eba37).
# Keyless sources only; no API keys configured.
ARG SUBFINDER_VERSION=2.17.0
ARG SUBFINDER_SHA256=a39c3e5c7a26ef3c430915c4d6cbf7716a00f26769a75e9405aba796142eba37
RUN curl -sSL "https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION}_linux_amd64.zip" -o /tmp/subfinder.zip \
    && echo "${SUBFINDER_SHA256}  /tmp/subfinder.zip" | sha256sum -c - \
    && unzip -o -q /tmp/subfinder.zip -d /tmp/subfinder_extract subfinder \
    && mv /tmp/subfinder_extract/subfinder /app/tools/subfinder \
    && chmod +x /app/tools/subfinder \
    && rm -rf /tmp/subfinder.zip /tmp/subfinder_extract \
    && /app/tools/subfinder -version

# Application code.
COPY app.py ./
COPY API_SPEC.md README.md ./

# Defaults (overridden by Render environment variables).
# PHONEINFOGA_BIN and SUBFINDER_BIN point at the binaries downloaded above.
# MAIGRET_BIN is the `maigret` console script from the pip install.
# USER_SCANNER_BIN is the `user-scanner` console script from the pip install.
# NUMVERIFY_API_KEY is set in the Render dashboard (free apilayer key);
# when absent, PhoneInfoga's numverify scanner is SKIP.
# GEOCODIO_API_KEY is set in the Render dashboard (free geocod.io key,
# 2,500 lookups/day); when absent, POST /address/verify falls back to
# the US Census Geocoder (no key) — never a fake clean.
ENV PHONEINFOGA_BIN=/app/tools/phoneinfoga \
    SUBFINDER_BIN=/app/tools/subfinder \
    MAIGRET_BIN=maigret \
    USER_SCANNER_BIN=user-scanner \
    MAIGRET_TOP_SITES=50 \
    MAIGRET_TIMEOUT=180 \
    PHONEINFOGA_TIMEOUT=90 \
    USER_SCANNER_TIMEOUT=240 \
    SUBFINDER_TIMEOUT=90 \
    SUBFINDER_MAX_RESULTS=500 \
    SUBFINDER_EXCLUDE_SOURCES=anubis,crtname,subdomaincenter \
    HTTP_TIMEOUT=15 \
    MAX_CONCURRENT_SCANS=3

# Render injects $PORT. Bind 0.0.0.0 so Render's router can reach us.
# SCAMINTEL_API_TOKEN, SUPABASE_URL and SUPABASE_SERVICE_KEY come from
# Render environment variables (never baked into the image).
CMD ["sh", "-c", "uvicorn app:app --host 0.0.0.0 --port ${PORT:-8000} --log-level info"]
