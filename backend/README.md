# Scam Intel API — Phase 1 Backend

The real scanner service for Scam Intel v3.0. FastAPI, binds `127.0.0.1`
only. Every completed scan writes a row to the Supabase `scans` table;
member-confirmed scams upsert into `verified_scams`.

## What is here

| File | What it is |
|------|-----------|
| `app.py` | The FastAPI service (all endpoints, validation, tools, Supabase writes). |
| `requirements.txt` | Python dependencies. |
| `run.sh` | Run script — creates the venv, installs deps, starts the service. |
| `.env.example` | Environment template (no real values — never commit a filled-in `.env`). |
| `API_SPEC.md` | Full endpoint / request / response / error documentation. |
| `test_api.py` | Validation test battery (same approach as Phase 0). |
| `tools/phoneinfoga` | PhoneInfoga v2.11.0 (Go binary, Linux x86_64). |
| `.venv/` | Python virtualenv (created by `run.sh`; not part of the deliverable). |

## Run on localhost

```bash
# 1. Copy the env template and fill in the real values.
cp .env.example .env
# Edit .env: SCAMINTEL_API_TOKEN, SUPABASE_URL, SUPABASE_SERVICE_KEY.
#   SUPABASE_URL is https://fcfsxgxqsownfywaokdp.supabase.co
#   SUPABASE_SERVICE_KEY is the project's service_role key.
#   Generate a token: python3 -c "import secrets; print(secrets.token_urlsafe(32))"

# 2. Start it (creates .venv + installs deps on first run).
./run.sh

# 3. Check it.
curl http://127.0.0.1:8000/health

# 4. Scan (replace TOKEN with your SCAMINTEL_API_TOKEN).
curl -X POST http://127.0.0.1:8000/scan/phone \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"target": "+15551234567"}'
```

The service prints its bearer token on startup if `SCAMINTEL_API_TOKEN`
is not set (random per run, dev convenience only).

## Tools — what actually runs

| Tool | Status in this VM |
|------|-------------------|
| PhoneInfoga v2.11.0 | Runs. Default scanners return Google-search URL lists unless API keys are configured. `phonenumbers` gives the reliable local carrier/region/validity signal. Its built-in numverify scanner is DISABLED (`-D numverify`): it calls a dead endpoint (api.apilayer.com/number_verification/validate, Cloudflare 504) and misreports it as "Invalid authentication credentials". Carrier/line-type comes from a direct Numverify API call instead (see below). |
| user-scanner 1.5.2.5 | Runs. Email registration check (220 modules, ~80 s) wired into `/scan/email`. NEVER run with `--hudson` (infostealer corpus — prohibited). Full username run (2,510+ sites) takes >4 min and is too slow for a synchronous call, so Maigret covers username. |
| subfinder v2.17.0 | Runs. Passive subdomain enumeration wired into `/scan/domain` (keyless sources only). In proxied environments the backend passes the egress proxy via subfinder's `-proxy` flag; on direct internet the flag is omitted. |
| crt.sh (direct HTTPS) | Works. Certificate-transparency subdomain data, a second subdomain source alongside subfinder in `/scan/domain`. |
| Maigret 0.6.6 | Runs. Top-50 sites in ~65 s; full 509-site run takes ~3–4 min (too slow for a synchronous call, so the API uses top-50). |
| phonenumbers 9.0.43 | Library, works locally, no network. |
| DNS | Real DNS via DNS-over-HTTPS (Google, then Cloudflare). The local system resolver returns synthetic proxy addresses, so DoH is used. |
| WHOIS / registrar | RDAP over HTTPS (rdap.org). Direct WHOIS (port 43) is blocked in this environment, so RDAP is the replacement. |
| Holehe, Sherlock | DROPPED per the architecture (deprecated/rotted). Not used. |
| theHarvester | BLOCKED (evaluated Nov 10, 2026). v4.11.1 installs and its CLI runs, but its keyless sources return empty even for github.com — its aiohttp client does not use the egress proxy, and even with a proxy configured in proxies.yaml the sources return nothing in <1 s. Its dependency pins (fastapi/uvicorn) conflict with this backend's venv, it pulls in Playwright, and current master needs Python 3.14 (this backend is 3.12). Its subdomain coverage is already provided by subfinder + crt.sh. Do not re-add without verifying it returns real data first. |

## Environment variables

| Variable | Default | Notes |
|----------|---------|-------|
| `SCAMINTEL_API_TOKEN` | (random per run) | Bearer token callers must send. |
| `SUPABASE_URL` | — | `https://fcfsxgxqsownfywaokdp.supabase.co` |
| `SUPABASE_SERVICE_KEY` | — | service_role key. Bypasses RLS. Backend env only. |
| `NUMVERIFY_API_KEY` | — | Free apilayer Numverify key. Unlocks the backend's direct Numverify API call (api.apilayer.net/numverify/api/validate) for carrier/line-type. Absent = SKIP. Invalid key = ERR (never a fake valid). |
| `SCAMINTEL_PORT` | `8000` | Binds 127.0.0.1 only. |
| `PHONEINFOGA_BIN` | `./tools/phoneinfoga` | Path to the PhoneInfoga v2 binary. |
| `SUBFINDER_BIN` | `./tools/subfinder` | Path to the subfinder binary. |
| `MAIGRET_BIN` | `maigret` | Maigret executable (from the venv). |
| `USER_SCANNER_BIN` | `user-scanner` | user-scanner executable (from the venv). |
| `MAIGRET_TOP_SITES` | `50` | Maigret site subset. |
| `MAIGRET_TIMEOUT` | `180` | Seconds. |
| `PHONEINFOGA_TIMEOUT` | `90` | Seconds. |
| `USER_SCANNER_TIMEOUT` | `240` | Seconds (email run takes ~80 s). |
| `SUBFINDER_TIMEOUT` | `90` | Seconds. |
| `SUBFINDER_MAX_RESULTS` | `500` | Max subdomains stored per scan (total count still recorded). |
| `HTTP_TIMEOUT` | `15` | Seconds (DoH / RDAP / Supabase / crt.sh). |
| `MAX_CONCURRENT_SCANS` | `3` | Concurrent scan cap. |

## Security notes

- No `shell=True` anywhere. Subprocess calls use argument lists only.
- All targets validated with the same regexes as the hardened v3.0 dev
  `server.py` before any tool runs.
- Bearer-token auth on every scan/report/check endpoint. Supabase JWT
  replaces it in Phase 2.
- The service_role key is read from the environment only. It is never
  printed, never written to a file, and never in a repo.
- RLS is enabled on `scans` and `verified_scams`. The backend writes
  with the service_role key (bypasses RLS). Members read their own
  scans and all of `verified_scams`; they cannot write directly.

## What is still needed to host it

The plan calls for a small VPS or container. This service is **not**
deployed anywhere — it runs on localhost only. To host it:

1. A small VPS/container with Python 3.12, the `tools/phoneinfoga`
   binary, and `maigret` installed (or build a Docker image from
   `requirements.txt` + the binary).
2. A non-root service user, run behind a reverse proxy with TLS
   (the service itself only binds 127.0.0.1).
3. The three secrets as environment variables on the host:
   `SCAMINTEL_API_TOKEN`, `SUPABASE_URL`, `SUPABASE_SERVICE_KEY`.
   (In Phase 2 the bearer token is replaced by Supabase JWT verification.)
4. A process manager (systemd / supervisor) to keep it running and
   restart it.
5. No hosting has been provisioned and no money spent — that is a
   separate decision for Josh.

## What is NOT done (later phases)

- Phase 2: Supabase JWT auth, `users` / `usage_quotas` / `payments`
  tables, human-review flag on `verified_scams`.
- Phase 3: Stripe gating + quota enforcement.
- Phase 4: the .store member dashboard wired to this API.
- Phase 5: Terms of Service / acceptable use (launch blocker).
