#!/usr/bin/env bash
# Scam Intel v3.0 — Phase 1 backend run script.
# Starts the FastAPI service on 127.0.0.1 only. Binds localhost — never
# expose publicly. The service_role key is read from the environment;
# it is never written into any file by this script.
#
# Usage:
#   SCAMINTEL_API_TOKEN=<token> SUPABASE_URL=<url> \
#   SUPABASE_SERVICE_KEY=<service_role_key> ./run.sh
#
# Or put the values in a .env file (see .env.example) and run:
#   set -a; source .env; set +a; ./run.sh
set -euo pipefail
cd "$(dirname "$0")"

# Create the venv on first run and install dependencies.
if [ ! -x ".venv/bin/python" ]; then
  echo "Creating virtualenv (.venv) and installing dependencies..."
  python3 -m venv .venv
  .venv/bin/pip install --quiet --upgrade pip
  .venv/bin/pip install --quiet -r requirements.txt
fi

# Maigret must be importable/runnable from the venv.
if ! .venv/bin/maigret --version >/dev/null 2>&1; then
  echo "Installing maigret into the venv..."
  .venv/bin/pip install --quiet maigret
fi

# PhoneInfoga v2 binary must exist (ships in ./tools/).
if [ ! -x "${PHONEINFOGA_BIN:-./tools/phoneinfoga}" ]; then
  echo "ERROR: PhoneInfoga binary not found at ${PHONEINFOGA_BIN:-./tools/phoneinfoga}" >&2
  echo "Download PhoneInfoga v2 (Linux x86_64) from" >&2
  echo "https://github.com/sundowndev/phoneinfoga/releases and place the" >&2
  echo "binary at ./tools/phoneinfoga (chmod +x)." >&2
  exit 1
fi

# subfinder binary must exist (ships in ./tools/).
if [ ! -x "${SUBFINDER_BIN:-./tools/subfinder}" ]; then
  echo "ERROR: subfinder binary not found at ${SUBFINDER_BIN:-./tools/subfinder}" >&2
  echo "Download subfinder v2 (Linux x86_64) from" >&2
  echo "https://github.com/projectdiscovery/subfinder/releases and place" >&2
  echo "the binary at ./tools/subfinder (chmod +x)." >&2
  exit 1
fi

# user-scanner must be importable/runnable from the venv.
if ! .venv/bin/user-scanner --version >/dev/null 2>&1; then
  echo "Installing user-scanner into the venv..."
  .venv/bin/pip install --quiet user-scanner
fi

export SCAMINTEL_PORT="${SCAMINTEL_PORT:-8000}"
exec .venv/bin/python app.py
