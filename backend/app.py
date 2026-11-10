#!/usr/bin/env python3
"""
Scam Intel v3.0 — Phase 1 Backend API (scan service)
TheCitizensMovement | thecitizenmovement.store

A sandboxed FastAPI scan service. Every completed scan writes a row to the
Supabase `scans` table (project fcfsxgxqsownfywaokdp). Member-confirmed
scams upsert into `verified_scams`, which powers the "known scam?" lookup.

Security properties:
  - No shell=True anywhere. All subprocess calls use argument lists.
  - Every target input is validated against a strict allowlist per kind
    (same regexes as the hardened v3.0 dev server.py).
  - API routes require a bearer token (SCAMINTEL_API_TOKEN). Supabase JWT
    verification replaces this in Phase 2 — not now.
  - Binds 127.0.0.1 only.
  - Per-scan timeouts, concurrency cap, no SSRF: the backend validates all
    input itself first; only allowlisted tool binaries / HTTPS endpoints
    make outbound calls.
  - Supabase service key lives in the environment only (never in code,
    never printed, never in a repo). The backend uses the service_role
    key, which bypasses RLS, so it can write to `scans`/`verified_scams`.

Tools (per ARCHITECTURE.md §2, plus Copilot's Nov 10, 2026 tooling report):
  - PhoneInfoga v2 (Go binary) — phone/carrier/VOIP lookups. Its
    built-in numverify scanner is DISABLED (-D numverify): it calls a
    dead endpoint (api.apilayer.com/number_verification/validate,
    Cloudflare 504) and misreports it as "Invalid authentication
    credentials". Carrier/line-type comes from a direct Numverify API
    call instead (see numverify_lookup).
  - Numverify (direct HTTPS call) — carrier/line-type/validity via
    https://api.apilayer.net/numverify/api/validate (free apilayer
    key, NUMVERIFY_API_KEY). Absent key = SKIP, invalid key = ERR.
  - Maigret — username checks (top-sites subset; full 509-site run is
    too slow for a synchronous API call).
  - user-scanner — email registration checks (210+ sites) and a second
    username engine (2,510+ sites). NEVER passes --hudson (infostealer
    corpus — prohibited).
  - subfinder (Go binary) — passive subdomain enumeration for the
    domain scan. Keyless sources only; no API keys configured.
  - crt.sh (direct HTTPS) — certificate-transparency subdomain data,
    a second subdomain source alongside subfinder.
  - Geocodio (direct HTTPS, API v2.1) — address verification,
    primary (free key, GEOCODIO_API_KEY, 2,500 lookups/day).
    Rooftop / parcel-centroid with a high score = FOUND; range
    interpolation = FOUND (weak); street-center / place / county /
    state centroid or no match = NONE; down or no key = SKIP.
  - US Census Geocoder (direct HTTPS, no key) — address second
    opinion / fallback. Existence/range only (TIGER interpolation),
    NOT deliverability.
  - Nominatim (direct HTTPS, no key) — address third opinion ONLY,
    when Geocodio and Census disagree. 1 request/sec, results
    cached, address text only (never a customer name).
  - usaddress (in-process) — address parsing only, never a verdict.
  - phonenumbers lib — phone parsing/validation/carrier.
  - DNS over HTTPS (Google/Cloudflare DoH) — real DNS. The local system
    resolver in this VM returns synthetic proxy addresses, so DoH is used.
  - RDAP over HTTPS (rdap.org) — registrar/status/creation data.
    Direct WHOIS (port 43) is blocked in this environment, so RDAP is
    the WHOIS replacement.
  - Holehe and Sherlock are DROPPED (deprecated/rotted) — not used.
  - theHarvester is BLOCKED (evaluated Nov 10, 2026): v4.11.1 installs
    and its CLI runs, but its keyless sources return empty even for
    github.com (aiohttp does not use the egress proxy; even with a
    proxy configured in proxies.yaml the sources return nothing in
    <1s). Its dependency pins (fastapi/uvicorn) conflict with this
    backend's venv, it pulls in Playwright, and current master needs
    Python 3.14 (this backend is 3.12). Its subdomain coverage is
    already provided by subfinder + crt.sh. Do not re-add without
    verifying it returns real data first.

Run:
  SCAMINTEL_API_TOKEN=<token> SUPABASE_URL=<url> \\
  SUPABASE_SERVICE_KEY=<service_role_key> ./run.sh
"""

import asyncio
import hashlib
import json
import os
import re
import secrets
import subprocess
import sys
import urllib.parse
from datetime import datetime, timezone

import httpx
import phonenumbers
from phonenumbers import carrier as pn_carrier
from phonenumbers import geocoder as pn_geocoder
from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

# ---------------------------------------------------------------------------
# Config (environment only — no secrets in code)
# ---------------------------------------------------------------------------
PORT = int(os.environ.get("SCAMINTEL_PORT", "8000"))
SUPABASE_URL = os.environ.get("SUPABASE_URL", "").rstrip("/")
SUPABASE_SERVICE_KEY = os.environ.get("SUPABASE_SERVICE_KEY", "")

# Bearer token: stable token from env, else a random one per run (dev).
API_TOKEN = os.environ.get("SCAMINTEL_API_TOKEN") or secrets.token_urlsafe(32)
TOKEN_WAS_GENERATED = "SCAMINTEL_API_TOKEN" not in os.environ

def _resolve_tool_bin(env_name, default_name):
    """Resolve a console-script binary (maigret, user-scanner).
    The backend is started as `.venv/bin/python app.py` without
    activating the venv, so the venv's bin dir is NOT on PATH and a bare
    name would not resolve. If the env var names a bare command, prefer
    the same directory as the running Python executable (the venv's bin)
    when the binary exists there; otherwise fall back to the bare name
    (PATH lookup — e.g. Docker, where pip installs to /usr/local/bin).
    An explicit path in the env var is used as-is."""
    value = os.environ.get(env_name, default_name)
    if os.sep in value:
        return value
    candidate = os.path.join(os.path.dirname(sys.executable), value)
    if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
        return candidate
    return value


# Tool paths / tunables (env-overridable, sane defaults).
PHONEINFOGA_BIN = os.environ.get(
    "PHONEINFOGA_BIN",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "tools", "phoneinfoga"),
)
MAIGRET_BIN = _resolve_tool_bin("MAIGRET_BIN", "maigret")
MAIGRET_TOP_SITES = int(os.environ.get("MAIGRET_TOP_SITES", "50"))
MAIGRET_TIMEOUT = int(os.environ.get("MAIGRET_TIMEOUT", "180"))
PHONEINFOGA_TIMEOUT = int(os.environ.get("PHONEINFOGA_TIMEOUT", "90"))
HTTP_TIMEOUT = float(os.environ.get("HTTP_TIMEOUT", "15"))
MAX_CONCURRENT_SCANS = int(os.environ.get("MAX_CONCURRENT_SCANS", "3"))

# user-scanner (email registration + second username engine).
# NEVER passes --hudson (infostealer corpus — prohibited).
USER_SCANNER_BIN = _resolve_tool_bin("USER_SCANNER_BIN", "user-scanner")
USER_SCANNER_TIMEOUT = int(os.environ.get("USER_SCANNER_TIMEOUT", "240"))

# subfinder (passive subdomain enumeration, Go binary).
SUBFINDER_BIN = os.environ.get(
    "SUBFINDER_BIN",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "tools", "subfinder"),
)
SUBFINDER_TIMEOUT = int(os.environ.get("SUBFINDER_TIMEOUT", "90"))
SUBFINDER_MAX_RESULTS = int(os.environ.get("SUBFINDER_MAX_RESULTS", "500"))
# Sources excluded from subfinder (comma-separated). anubis, crtname and
# subdomaincenter return tens of thousands of synthetic/bogus subdomains
# for ordinary domains (e.g. anubis returned 22,248 for example.com,
# which has 6 real subdomains in crt.sh). Excluding them keeps the
# results to sources that return real certificate/passive-DNS data.
SUBFINDER_EXCLUDE_SOURCES = os.environ.get(
    "SUBFINDER_EXCLUDE_SOURCES", "anubis,crtname,subdomaincenter"
)

# Numverify (free apilayer key) — carrier/line-type via a DIRECT API
# call (see numverify_lookup). PhoneInfoga's built-in numverify scanner
# is NOT used: it calls the dead endpoint
# https://api.apilayer.com/number_verification/validate (Cloudflare
# 504) and misreports the failure as "Invalid authentication
# credentials". The working endpoint, confirmed live Nov 10, 2026, is
# https://api.apilayer.net/numverify/api/validate. Absent key = SKIP
# (never fake clean). The key is read from the environment only and
# is never logged or returned. Never hardcode it.
NUMVERIFY_API_KEY = os.environ.get("NUMVERIFY_API_KEY", "")
NUMVERIFY_URL = "https://api.apilayer.net/numverify/api/validate"
NUMVERIFY_TIMEOUT = int(os.environ.get("NUMVERIFY_TIMEOUT", "15"))

# Geocodio (free key) — primary address verification, API v2.1
# (https://api.geocod.io/v2.1/geocode, current docs Nov 10, 2026).
# Rooftop (parcel centroid arrives as match_type, with
# accuracy_type rooftop) with a high accuracy score = FOUND; range
# interpolation = FOUND (weak); street-center / place / county /
# state centroid or no match = NONE; down or no key = SKIP. The key
# is read from the environment only and is never logged or returned.
# Never hardcode it. Free tier: 2,500 lookups/day, no card.
GEOCODIO_API_KEY = os.environ.get("GEOCODIO_API_KEY", "")
GEOCODIO_URL = "https://api.geocod.io/v2.1/geocode"
GEOCODIO_TIMEOUT = int(os.environ.get("GEOCODIO_TIMEOUT", "15"))
GEOCODIO_FOUND_MIN_SCORE = float(os.environ.get("GEOCODIO_FOUND_MIN_SCORE", "0.8"))

# US Census Geocoder (free, no key) — address second opinion /
# fallback. Existence/range only (TIGER interpolation), NOT
# deliverability. A match is FOUND (weak); no match is NONE.
CENSUS_URL = "https://geocoding.geo.census.gov/geocoder/locations/onelineaddress"
CENSUS_TIMEOUT = int(os.environ.get("CENSUS_TIMEOUT", "15"))

# Nominatim (free, no key) — address third opinion ONLY. Usage
# policy (operations.osmfoundation.org/policies/nominatim/): max 1
# request/sec for the whole application, a valid User-Agent
# identifying the application is required, results must be cached,
# address text only (never a customer name or other personal data).
# Called only when Geocodio and Census disagree, or when both are
# unavailable. Never the primary check.
NOMINATIM_URL = "https://nominatim.openstreetmap.org/search"
NOMINATIM_USER_AGENT = os.environ.get(
    "NOMINATIM_USER_AGENT", "ScamIntel/3.0 (thecitizenmovement.store)"
)
NOMINATIM_TIMEOUT = int(os.environ.get("NOMINATIM_TIMEOUT", "15"))
NOMINATIM_MIN_INTERVAL = 1.0  # seconds between requests (policy max 1/sec)
NOMINATIM_CACHE_TTL = int(os.environ.get("NOMINATIM_CACHE_TTL", "86400"))  # 24h
NOMINATIM_CACHE_MAX = 1000

# DoH resolvers (JSON API). Google first, Cloudflare fallback.
DOH_URLS = [
    "https://dns.google/resolve",
    "https://cloudflare-dns.com/dns-query",
]

# ---------------------------------------------------------------------------
# Input validation (same regexes as hardened v3.0 server.py)
# ---------------------------------------------------------------------------
PHONE_RE = re.compile(r"^\+?[0-9][0-9\-\.\s\(\)]{3,24}$")
EMAIL_RE = re.compile(
    r"^[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,253}\.[A-Za-z]{2,}$"
)
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,64}$")
# US street address: letters/digits plus . , # / ' - ( ) and spaces.
# No shell metachars, no control characters. At least one letter.
ADDRESS_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 .,#/'\-()]{0,252}$")


def validate_target(kind, target):
    """Return True if target is acceptable for the given kind."""
    if not isinstance(target, str) or not target:
        return False
    t = target.strip()
    if kind == "phone":
        return bool(PHONE_RE.match(t))
    if kind == "email":
        return bool(EMAIL_RE.match(t))
    if kind == "domain":
        return bool(DOMAIN_RE.match(t)) and "." in t
    if kind == "username":
        return bool(USERNAME_RE.match(t))
    if kind == "address":
        return bool(ADDRESS_RE.match(t)) and any(c.isalpha() for c in t)
    return False


# ---------------------------------------------------------------------------
# App + auth
# ---------------------------------------------------------------------------
app = FastAPI(
    title="Scam Intel API",
    version="3.0.0-phase1.3",
    description="Phase 1 scan backend for Scam Intel v3.0. Binds localhost only.",
)
security = HTTPBearer(auto_error=False)
_scan_semaphore = asyncio.Semaphore(MAX_CONCURRENT_SCANS)


async def require_token(
    credentials: HTTPAuthorizationCredentials = Depends(security),
):
    """Bearer-token auth (same pattern as hardened server.py)."""
    token = credentials.credentials if credentials else ""
    if not token or not secrets.compare_digest(token, API_TOKEN):
        raise HTTPException(status_code=401, detail="Unauthorized")
    return True


def _supabase_headers():
    return {
        "apikey": SUPABASE_SERVICE_KEY,
        "Authorization": f"Bearer {SUPABASE_SERVICE_KEY}",
        "Content-Type": "application/json",
        "Prefer": "return=representation",
    }


def _supabase_configured():
    return bool(SUPABASE_URL and SUPABASE_SERVICE_KEY)


def _make_http_client(timeout=HTTP_TIMEOUT):
    """httpx client that does NOT read proxy env vars (the runtime's
    NO_PROXY list contains bracketed IPv6 entries that httpx cannot
    parse) and instead uses the egress proxy explicitly when set.
    External HTTPS calls (Supabase, DoH, RDAP) go through the proxy;
    without it they cannot leave this VM.
    TLS: the runtime's egress proxy MITMs some hosts (e.g.
    geocoding.geo.census.gov, api.apilayer.net) with a CA the default
    certifi bundle does not trust. The runtime publishes its CA
    bundle at SSL_CERT_FILE (the same bundle curl uses); use it when
    present, otherwise default verification. On Render the variable
    is unset and this is a no-op."""
    proxy = (
        os.environ.get("https_proxy")
        or os.environ.get("HTTPS_PROXY")
        or os.environ.get("http_proxy")
        or os.environ.get("HTTP_PROXY")
    )
    verify = True
    ca_bundle = os.environ.get("SSL_CERT_FILE", "")
    if ca_bundle and os.path.isfile(ca_bundle):
        verify = ca_bundle
    return httpx.AsyncClient(timeout=timeout, trust_env=False, proxy=proxy,
                             verify=verify)


# ---------------------------------------------------------------------------
# Supabase helpers (service_role via REST — bypasses RLS)
# ---------------------------------------------------------------------------
async def supabase_insert_scan(tool, target, target_type, result_summary,
                               result, status="complete", user_id=None):
    """Insert one row into `scans`. Returns the created row (dict) or None
    if Supabase is not configured / the insert fails."""
    if not _supabase_configured():
        return None
    payload = {
        "tool": tool,
        "target": target,
        "target_type": target_type,
        "result_summary": result_summary,
        "result": result,
        "status": status,
        "user_id": user_id,
    }
    try:
        async with _make_http_client() as client:
            resp = await client.post(
                f"{SUPABASE_URL}/rest/v1/scans",
                headers=_supabase_headers(),
                json=payload,
            )
            resp.raise_for_status()
            rows = resp.json()
            return rows[0] if rows else None
    except Exception:
        return None


async def supabase_lookup_verified(target, target_type=None):
    """Look up a target in `verified_scams`. Returns the row or None."""
    if not _supabase_configured():
        return None
    # Case-insensitive exact match on target; filter by type when given.
    params = {"target": f"ilike.{target}"}
    if target_type:
        params["target_type"] = f"eq.{target_type}"
    try:
        async with _make_http_client() as client:
            resp = await client.get(
                f"{SUPABASE_URL}/rest/v1/verified_scams",
                headers=_supabase_headers(),
                params=params,
            )
            resp.raise_for_status()
            rows = resp.json()
            return rows[0] if rows else None
    except Exception:
        return None


async def supabase_upsert_verified(target, target_type, evidence):
    """Upsert a member-confirmed scam into `verified_scams`. Increments
    reporter_count and refreshes last_seen when the target already exists.
    Returns the row or None."""
    if not _supabase_configured():
        return None
    existing = await supabase_lookup_verified(target, target_type)
    try:
        async with _make_http_client() as client:
            if existing:
                new_count = int(existing.get("reporter_count") or 1) + 1
                resp = await client.patch(
                    f"{SUPABASE_URL}/rest/v1/verified_scams",
                    headers=_supabase_headers(),
                    params={"id": f"eq.{existing['id']}"},
                    json={
                        "reporter_count": new_count,
                        "last_seen": "now()",
                        "evidence": evidence or existing.get("evidence"),
                    },
                )
                resp.raise_for_status()
                rows = resp.json()
                return rows[0] if rows else existing
            resp = await client.post(
                f"{SUPABASE_URL}/rest/v1/verified_scams",
                headers=_supabase_headers(),
                json={
                    "target": target,
                    "target_type": target_type,
                    "evidence": evidence,
                    "reporter_count": 1,
                },
            )
            resp.raise_for_status()
            rows = resp.json()
            return rows[0] if rows else None
    except Exception:
        return None


async def supabase_lookup_valid(target, target_type=None):
    """Look up a target in `verified_valid` (the good list). Returns
    the row or None."""
    if not _supabase_configured():
        return None
    params = {"target": f"ilike.{target}"}
    if target_type:
        params["target_type"] = f"eq.{target_type}"
    try:
        async with _make_http_client() as client:
            resp = await client.get(
                f"{SUPABASE_URL}/rest/v1/verified_valid",
                headers=_supabase_headers(),
                params=params,
            )
            resp.raise_for_status()
            rows = resp.json()
            return rows[0] if rows else None
    except Exception:
        return None


async def supabase_upsert_valid(target, target_type, verified_via, details,
                                evidence):
    """Upsert a verified-good target into `verified_valid`. Refreshes
    last_seen, verified_via and details when the target already
    exists (UNIQUE(target, target_type)). Returns the row or None."""
    if not _supabase_configured():
        return None
    existing = await supabase_lookup_valid(target, target_type)
    try:
        async with _make_http_client() as client:
            if existing:
                resp = await client.patch(
                    f"{SUPABASE_URL}/rest/v1/verified_valid",
                    headers=_supabase_headers(),
                    params={"id": f"eq.{existing['id']}"},
                    json={
                        "verified_via": verified_via,
                        "details": details,
                        "evidence": evidence or existing.get("evidence"),
                        "last_seen": "now()",
                    },
                )
                resp.raise_for_status()
                rows = resp.json()
                return rows[0] if rows else existing
            resp = await client.post(
                f"{SUPABASE_URL}/rest/v1/verified_valid",
                headers=_supabase_headers(),
                json={
                    "target": target,
                    "target_type": target_type,
                    "verified_via": verified_via,
                    "details": details,
                    "evidence": evidence,
                },
            )
            resp.raise_for_status()
            rows = resp.json()
            return rows[0] if rows else None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Tool runners (subprocess arg-lists ONLY — never shell=True)
# ---------------------------------------------------------------------------
def _utc_now():
    """Current UTC timestamp (ISO 8601, Z suffix) for provenance."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _clean_proxy_env():
    """Copy of os.environ with a sanitized NO_PROXY.
    user-scanner's HTTP stack chokes on the bracketed IPv6 entries
    (e.g. [::1]) in the runtime's NO_PROXY list ('Invalid port' errors
    on some modules). A plain host list avoids that without changing
    proxy routing."""
    env = dict(os.environ)
    env["NO_PROXY"] = "localhost,127.0.0.1"
    env["no_proxy"] = "localhost,127.0.0.1"
    return env


def _egress_proxy():
    """Egress proxy URL from the environment, if set.
    Some Go tools (subfinder) do not read the proxy env vars themselves,
    so the backend passes it explicitly via their -proxy flag. Never
    logged. Empty string when no proxy is configured (e.g. Render,
    which has direct internet)."""
    return (
        os.environ.get("https_proxy")
        or os.environ.get("HTTPS_PROXY")
        or os.environ.get("http_proxy")
        or os.environ.get("HTTP_PROXY")
        or ""
    )


def run_cmd(argv, timeout, env=None):
    """Run a command given as an argument LIST. Returns (output, ok).
    Never a shell string. env, when given, replaces the subprocess
    environment (used to sanitize NO_PROXY for user-scanner); when
    None the subprocess inherits the parent environment (which is how
    NUMVERIFY_API_KEY reaches PhoneInfoga)."""
    if not isinstance(argv, (list, tuple)) or not argv:
        return "[ERROR] Invalid command.", False
    try:
        result = subprocess.run(
            list(argv), shell=False, capture_output=True, text=True,
            timeout=timeout, env=env,
        )
        return (result.stdout + result.stderr), result.returncode == 0
    except subprocess.TimeoutExpired:
        return "[TIMEOUT] Command took too long.", False
    except FileNotFoundError:
        return f"[ERROR] Tool not installed: {argv[0]}", False
    except Exception as e:
        return f"[ERROR] {str(e)}", False


async def run_cmd_async(argv, timeout, env=None):
    """Run run_cmd in a thread so the event loop is not blocked."""
    return await asyncio.to_thread(run_cmd, argv, timeout, env)


# ---------------------------------------------------------------------------
# DNS over HTTPS (local resolver returns synthetic proxy addresses)
# ---------------------------------------------------------------------------
async def doh_lookup(name, rtype):
    """DNS lookup via DoH (Google, then Cloudflare). Returns a list of
    answer strings, or [] when none. rtype: 'A', 'MX', 'TXT', 'AAAA'."""
    type_map = {"A": 1, "AAAA": 28, "MX": 15, "TXT": 16}
    qtype = type_map.get(rtype.upper(), 1)
    async with _make_http_client() as client:
        for base in DOH_URLS:
            try:
                headers = {}
                if "cloudflare" in base:
                    headers["accept"] = "application/dns-json"
                resp = await client.get(
                    base, params={"name": name, "type": qtype},
                    headers=headers,
                )
                resp.raise_for_status()
                data = resp.json()
                answers = []
                for ans in data.get("Answer", []) or []:
                    answers.append(str(ans.get("data", "")))
                return answers
            except Exception:
                continue
    return []


async def rdap_lookup(domain):
    """Registrar/status data via RDAP over HTTPS (rdap.org, follows the
    redirect to the authoritative RDAP server). Returns a dict or None.
    Direct WHOIS (port 43) is blocked in this environment."""
    try:
        async with _make_http_client() as client:
            resp = await client.get(
                f"https://rdap.org/domain/{domain}",
                follow_redirects=True,
                headers={"accept": "application/rdap+json"},
            )
            resp.raise_for_status()
            data = resp.json()
            registrar = None
            for ent in data.get("entities", []) or []:
                if "registrar" in (ent.get("roles") or []):
                    for v in (ent.get("vcardArray", [None, []])[1] or []):
                        if v and v[0] == "fn":
                            registrar = v[3]
                            break
                    break
            events = {}
            for ev in data.get("events", []) or []:
                events[ev.get("eventAction")] = ev.get("eventDate")
            return {
                "registrar": registrar,
                "status": data.get("status", []),
                "creation_date": events.get("registration"),
                "expiration_date": events.get("expiration"),
                "last_changed": events.get("last changed"),
                "handle": data.get("handle"),
            }
    except Exception:
        return None


async def crtsh_lookup(domain):
    """Certificate-transparency subdomain data, direct HTTPS (crt.sh).
    A second subdomain source alongside subfinder; uses the backend's
    working httpx client (proxy-aware), so it works even where the
    subfinder binary's sources are unreachable. Returns a dict with
    status (FOUND/NONE/SKIP/ERR), subdomains, and provenance."""
    checked_at = _utc_now()
    result = {
        "tool": "crtsh",
        "source": "https://crt.sh",
        "status": "ERR",
        "checked_at": checked_at,
        "subdomains": [],
        "total_found": 0,
    }
    try:
        async with _make_http_client() as client:
            resp = await client.get(
                "https://crt.sh/",
                params={"q": f"%.{domain}", "output": "json"},
            )
            resp.raise_for_status()
            data = resp.json()
    except Exception as e:
        result["reason"] = f"crt.sh request failed: {e}"
        return result
    names = set()
    for entry in data or []:
        nv = str(entry.get("name_value", "") or "")
        for line in nv.splitlines():
            name = line.strip().lower()
            if not name:
                continue
            if name.startswith("*."):
                name = name[2:]
            if name and name.endswith("." + domain.lower()):
                names.add(name)
    subs = sorted(names)
    result["subdomains"] = subs
    result["total_found"] = len(subs)
    result["status"] = "FOUND" if subs else "NONE"
    return result


# ---------------------------------------------------------------------------
# Numverify (direct API call — carrier/line-type for phone scans)
# ---------------------------------------------------------------------------
async def numverify_lookup(number):
    """Carrier/line-type/validity via the Numverify API, called DIRECTLY.
    PhoneInfoga's built-in numverify scanner calls the dead endpoint
    https://api.apilayer.com/number_verification/validate (Cloudflare
    504) and misreports the failure as "Invalid authentication
    credentials", so the backend does not rely on it. The working
    endpoint, confirmed live Nov 10, 2026 (direct browser test, quota
    0/100 -> 2/100), is https://api.apilayer.net/numverify/api/validate
    with access_key + number as query params.
    Returns a dict keeping the existing numverify shape (enabled,
    status, checked_at, note, output) plus the API's fields (valid,
    country_code, country_name, location, carrier, line_type) and the
    full API JSON under "details" on success. Status: "ran" on a real
    API answer (even valid=false for fictional numbers — that is real
    data), "ERR" on any failure (never a fake valid), "SKIP" when no
    key is set. The key is never logged or returned."""
    checked_at = _utc_now()
    base = {
        "enabled": bool(NUMVERIFY_API_KEY),
        "checked_at": checked_at,
        "note": "carrier/line-type via Numverify (free key set)",
    }
    if not NUMVERIFY_API_KEY:
        return {
            **base,
            "enabled": False,
            "status": "SKIP",
            "reason": "NUMVERIFY_API_KEY not set (free key from apilayer.com unlocks carrier/line-type)",
        }
    try:
        async with _make_http_client(timeout=NUMVERIFY_TIMEOUT) as client:
            resp = await client.get(
                NUMVERIFY_URL,
                params={"access_key": NUMVERIFY_API_KEY, "number": number},
            )
            resp.raise_for_status()
            data = resp.json()
    except Exception as e:
        return {
            **base,
            "status": "ERR",
            "reason": f"Numverify request failed: {e}"[:500],
        }
    if not isinstance(data, dict) or data.get("success") is False:
        err = (data or {}).get("error") or {}
        return {
            **base,
            "status": "ERR",
            "reason": (
                f"Numverify API error {err.get('code')}: {err.get('type')}"
            )[:500],
        }
    # Real answer — even valid=false is real data (e.g. fictional 555
    # numbers). Never claim more than the API returned.
    fields = {
        "valid": data.get("valid"),
        "country_code": data.get("country_code"),
        "country_name": data.get("country_name"),
        "location": data.get("location"),
        "carrier": data.get("carrier"),
        "line_type": data.get("line_type"),
    }
    summary = (
        f"valid={fields['valid']}; country_code={fields['country_code']}; "
        f"country_name={fields['country_name']}; location={fields['location']}; "
        f"carrier={fields['carrier']}; line_type={fields['line_type']}"
    )
    return {**base, "status": "ran", "output": summary, **fields, "details": data}


# ---------------------------------------------------------------------------
# user-scanner (email registration + username) — NEVER passes --hudson
# ---------------------------------------------------------------------------
async def run_user_scanner(target, kind):
    """user-scanner registration check (email or username).
    NEVER passes --hudson: that flag queries Hudson Rock infostealer
    malware logs, which is an infostealer corpus and is prohibited.
    kind: 'email' or 'username'.
    Returns a dict with status (FOUND/NONE/SKIP/ERR), the registered
    sites (each with site URL for provenance), counts, and a UTC
    timestamp. A module that errors is ERR for that module, never a
    fake 'not registered'."""
    out_dir = "/tmp/user_scanner_reports"
    os.makedirs(out_dir, exist_ok=True)
    tag = hashlib.sha256(f"{kind}:{target}".encode()).hexdigest()[:12]
    out_path = os.path.join(out_dir, f"us_{tag}.json")
    if kind == "email":
        argv = [USER_SCANNER_BIN, "-e", target, "-f", "json", "-o", out_path]
    else:
        argv = [USER_SCANNER_BIN, "-u", target, "-f", "json", "-o", out_path]
    # NOTE: --hudson is NEVER passed (see docstring above).
    output, ok = await run_cmd_async(
        argv, USER_SCANNER_TIMEOUT, env=_clean_proxy_env()
    )
    checked_at = _utc_now()
    result = {
        "tool": "user-scanner",
        "kind": kind,
        "ran": ok,
        "status": "ERR",
        "checked_at": checked_at,
        "registered": [],
        "registered_count": 0,
        "not_registered_count": 0,
        "error_count": 0,
        "skipped_count": 0,
        "total_modules": 0,
        "errors": [],
    }
    if not ok:
        if "not installed" in output.lower() or "no such file" in output.lower():
            result["status"] = "SKIP"
            result["reason"] = "user-scanner not installed"
        elif "[TIMEOUT]" in output:
            result["status"] = "ERR"
            result["reason"] = "user-scanner timed out"
        else:
            result["status"] = "ERR"
            result["reason"] = output[:500]
        return result
    try:
        with open(out_path) as f:
            items = json.load(f)
    except Exception as e:
        result["status"] = "ERR"
        result["reason"] = f"could not parse user-scanner output: {e}"
        return result
    finally:
        try:
            os.remove(out_path)
        except OSError:
            pass
    registered = []
    errors = []
    counts = {"Registered": 0, "Not Registered": 0, "Error": 0, "Skipped": 0}
    for item in items or []:
        if not isinstance(item, dict):
            continue
        status = str(item.get("status", ""))
        site = str(item.get("site_name", ""))
        if status == "Registered":
            counts["Registered"] += 1
            extra = item.get("extra") or {}
            profile = (
                extra.get("profile")
                or extra.get("url")
                or item.get("url")
                or ""
            )
            registered.append({
                "site": site,
                "category": str(item.get("category", "")),
                "url": str(item.get("url", "")),
                "profile": str(profile),
                "login": str(extra.get("login", "")) if extra.get("login") else "",
            })
        elif status in ("Not Registered", "Not Found"):
            counts["Not Registered"] += 1
        elif status == "Error":
            counts["Error"] += 1
            errors.append({
                "site": site,
                "reason": str(item.get("reason", ""))[:200],
            })
        elif status == "Skipped":
            counts["Skipped"] += 1
        else:
            counts["Error"] += 1
            errors.append({
                "site": site,
                "reason": f"unexpected status: {status}",
            })
    result["total_modules"] = len(items or [])
    result["registered"] = registered
    result["registered_count"] = counts["Registered"]
    result["not_registered_count"] = counts["Not Registered"]
    result["error_count"] = counts["Error"]
    result["skipped_count"] = counts["Skipped"]
    # Cap the stored error list (220 modules can produce many errors).
    result["errors"] = errors[:50]
    result["errors_truncated"] = len(errors) > 50
    if counts["Registered"] > 0:
        result["status"] = "FOUND"
    elif counts["Not Registered"] > 0:
        result["status"] = "NONE"
    elif counts["Error"] + counts["Skipped"] > 0 and (
        counts["Error"] + counts["Skipped"] == result["total_modules"]
    ):
        # No module gave a definitive answer — cannot determine.
        result["status"] = "ERR"
        result["reason"] = "no module returned a definitive answer"
    else:
        result["status"] = "ERR"
        result["reason"] = "no definitive result"
    return result


# ---------------------------------------------------------------------------
# subfinder (passive subdomain enumeration)
# ---------------------------------------------------------------------------
async def run_subfinder(domain):
    """subfinder subdomain enumeration (Go binary, arg-list).
    Keyless sources only; no API keys configured (keyed sources are
    reported as skipped by subfinder, never as 'no subdomains').
    Passes the egress proxy explicitly via -proxy when one is set in
    the environment (subfinder does not read the proxy env vars itself).
    Returns a dict with status (FOUND/NONE/SKIP/ERR), subdomains
    (capped), total count, and a UTC timestamp."""
    checked_at = _utc_now()
    result = {
        "tool": "subfinder",
        "status": "ERR",
        "checked_at": checked_at,
        "subdomains": [],
        "total_found": 0,
        "truncated": False,
    }
    argv = [SUBFINDER_BIN, "-d", domain, "-silent"]
    if SUBFINDER_EXCLUDE_SOURCES:
        argv += ["-exclude-sources", SUBFINDER_EXCLUDE_SOURCES]
    proxy = _egress_proxy()
    if proxy:
        # Passed as an argv value (never logged). subfinder needs this
        # in proxied environments; on direct internet it is omitted.
        argv += ["-proxy", proxy]
    output, ok = await run_cmd_async(argv, SUBFINDER_TIMEOUT)
    if not ok:
        if "not installed" in output.lower() or "no such file" in output.lower():
            result["status"] = "SKIP"
            result["reason"] = "subfinder not installed"
        elif "[TIMEOUT]" in output:
            result["status"] = "ERR"
            result["reason"] = "subfinder timed out"
        else:
            result["status"] = "ERR"
            result["reason"] = output[:500]
        return result
    names = set()
    for line in (output or "").splitlines():
        name = line.strip().lower()
        if not name:
            continue
        # subfinder -silent prints one subdomain per line; ignore any
        # log lines (they start with '[').
        if name.startswith("["):
            continue
        names.add(name)
    subs = sorted(names)
    result["total_found"] = len(subs)
    if len(subs) > SUBFINDER_MAX_RESULTS:
        result["subdomains"] = subs[:SUBFINDER_MAX_RESULTS]
        result["truncated"] = True
    else:
        result["subdomains"] = subs
    result["status"] = "FOUND" if subs else "NONE"
    return result


# ---------------------------------------------------------------------------
# Address verification (Geocodio primary, Census fallback, Nominatim
# third opinion) — POST /address/verify
# ---------------------------------------------------------------------------
try:
    import usaddress as _usaddress
except Exception:  # missing dep is a SKIP for the parse step, not a crash
    _usaddress = None


def parse_address(address):
    """Parse a US address string into components with usaddress
    (in-process, no network). Parsing only — never a verdict by
    itself. Returns a dict with components, a parseable flag, and a
    UTC timestamp. usaddress missing = SKIP (the API calls still run;
    Geocodio does its own parsing)."""
    checked_at = _utc_now()
    result = {
        "tool": "usaddress",
        "status": "SKIP",
        "checked_at": checked_at,
        "components": {},
        "parseable": False,
    }
    if _usaddress is None:
        result["reason"] = "usaddress not installed"
        return result
    try:
        tagged = _usaddress.parse(address)
    except Exception as e:
        result["status"] = "ERR"
        result["reason"] = f"usaddress parse failed: {e}"[:300]
        return result
    components = {}
    for value, label in tagged:
        clean = value.strip().strip(",")
        if not clean:
            continue
        # A label can repeat (e.g. two PlaceName tokens); join repeats.
        if label in components:
            components[label] = f"{components[label]} {clean}"
        else:
            components[label] = clean
    result["components"] = components
    has_number = bool(components.get("AddressNumber"))
    has_street = bool(components.get("StreetName"))
    result["parseable"] = bool(has_number and has_street)
    result["status"] = "FOUND" if result["parseable"] else "NONE"
    if not result["parseable"]:
        result["reason"] = (
            "no street number + street name parsed "
            "(geocoders still attempted)"
        )
    return result


async def geocodio_lookup(address):
    """Verify an address with Geocodio (API v2.1, direct HTTPS).
    Returns a dict with status (FOUND/NONE/SKIP/ERR), the
    standardized address, accuracy score/type, match_type, and
    provenance. Verdict mapping (accuracy_type values from the
    Geocodio docs, current Nov 10, 2026):
      rooftop (parcel centroid arrives as match_type, with
        accuracy_type rooftop) with score >= GEOCODIO_FOUND_MIN_SCORE
        -> FOUND
      range_interpolation with score >= threshold -> FOUND (weak)
      street_center / place / county / state / nearest_* /
        intersection / point / coordinate / no results -> NONE
    No key = SKIP (no network call, never a fake clean). Any failed
    call (bad key, 403, 429, timeout) = ERR."""
    checked_at = _utc_now()
    base = {
        "tool": "geocodio",
        "source": GEOCODIO_URL,
        "status": "SKIP",
        "checked_at": checked_at,
        "standardized_address": None,
        "accuracy": None,
        "accuracy_type": None,
        "match_type": None,
    }
    if not GEOCODIO_API_KEY:
        base["reason"] = (
            "GEOCODIO_API_KEY not set "
            "(free key from geocod.io unlocks address verification)"
        )
        return base
    try:
        async with _make_http_client(timeout=GEOCODIO_TIMEOUT) as client:
            resp = await client.get(
                GEOCODIO_URL,
                params={"q": address, "api_key": GEOCODIO_API_KEY},
            )
            resp.raise_for_status()
            data = resp.json()
    except Exception as e:
        return {
            **base, "status": "ERR",
            "reason": f"Geocodio request failed: {e}"[:500],
        }
    results = (data or {}).get("results") or []
    if not results:
        return {**base, "status": "NONE",
                "reason": "Geocodio returned no match"}
    top = results[0] if isinstance(results[0], dict) else {}
    accuracy = top.get("accuracy")
    accuracy_type = top.get("accuracy_type")
    match_type = top.get("match_type")
    try:
        score_ok = (
            accuracy is None
            or float(accuracy) >= GEOCODIO_FOUND_MIN_SCORE
        )
    except (TypeError, ValueError):
        score_ok = False
    out = {
        **base,
        "standardized_address": top.get("formatted_address"),
        "accuracy": accuracy,
        "accuracy_type": accuracy_type,
        "match_type": match_type,
        "location": top.get("location"),
        "source_name": top.get("source"),
    }
    if accuracy_type == "rooftop" and score_ok:
        out["status"] = "FOUND"
        if match_type == "parcel_centroid":
            out["note"] = "parcel-centroid match"
    elif accuracy_type == "range_interpolation" and score_ok:
        out["status"] = "FOUND"
        out["weak"] = True
        out["note"] = (
            "range interpolation — street and range exist, exact number "
            "interpolated (weaker than rooftop)"
        )
    else:
        out["status"] = "NONE"
        out["reason"] = (
            f"no street-level match (accuracy_type={accuracy_type}, "
            f"accuracy={accuracy})"
        )
    return out


async def census_lookup(address):
    """Second opinion / fallback: US Census Geocoder (free, no key).
    Confirms the address falls on a real TIGER street range — an
    existence/range check, NOT deliverability. A match is FOUND
    (weak, recorded as such); no match is NONE; a failed call is
    ERR."""
    checked_at = _utc_now()
    base = {
        "tool": "census",
        "source": CENSUS_URL,
        "status": "ERR",
        "checked_at": checked_at,
        "standardized_address": None,
        "accuracy": None,
        "accuracy_type": "range",
        "note": "existence/range only (TIGER interpolation) — "
                "NOT deliverability",
    }
    try:
        async with _make_http_client(timeout=CENSUS_TIMEOUT) as client:
            resp = await client.get(
                CENSUS_URL,
                params={
                    "address": address,
                    "benchmark": "Public_AR_Current",
                    "format": "json",
                },
            )
            resp.raise_for_status()
            data = resp.json()
    except Exception as e:
        return {
            **base,
            "reason": f"Census Geocoder request failed: {e}"[:500],
        }
    matches = ((data or {}).get("result") or {}).get("addressMatches") or []
    if not matches:
        return {
            **base, "status": "NONE",
            "reason": "Census Geocoder returned no match",
        }
    top = matches[0] if isinstance(matches[0], dict) else {}
    return {
        **base,
        "status": "FOUND",
        "standardized_address": top.get("matchedAddress"),
        "coordinates": top.get("coordinates"),
        "tiger_line": top.get("tigerLine"),
    }


# Nominatim rate limiting (policy: max 1 request/sec, whole app) and
# cache (policy: results must be cached). In-memory only; the process
# is single-instance on Render free tier.
_nominatim_lock = asyncio.Lock()
_nominatim_last_call = 0.0
_nominatim_cache = {}


def _nominatim_cache_get(key):
    entry = _nominatim_cache.get(key)
    if not entry:
        return None
    result, stored_at = entry
    if (datetime.now(timezone.utc).timestamp() - stored_at) > NOMINATIM_CACHE_TTL:
        _nominatim_cache.pop(key, None)
        return None
    return result


def _nominatim_cache_put(key, result):
    # Only cache definitive answers (FOUND/NONE); never cache an ERR.
    if result.get("status") not in ("FOUND", "NONE"):
        return
    if len(_nominatim_cache) >= NOMINATIM_CACHE_MAX:
        oldest = min(_nominatim_cache, key=lambda k: _nominatim_cache[k][1])
        _nominatim_cache.pop(oldest, None)
    _nominatim_cache[key] = (result, datetime.now(timezone.utc).timestamp())


async def nominatim_lookup(address):
    """Third opinion ONLY: OpenStreetMap Nominatim (free, no key).
    Called only when Geocodio and Census disagree, or when both are
    unavailable. Policy: max 1 request/sec (enforced with a lock),
    descriptive User-Agent, results cached, ADDRESS TEXT ONLY — never
    a customer name or any other personal data. A match confirms
    existence in OSM data, not deliverability."""
    global _nominatim_last_call
    checked_at = _utc_now()
    base = {
        "tool": "nominatim",
        "source": NOMINATIM_URL,
        "status": "ERR",
        "checked_at": checked_at,
        "standardized_address": None,
        "accuracy": None,
        "accuracy_type": "existence",
        "note": "existence in OSM data only — NOT deliverability",
    }
    cache_key = hashlib.sha256(address.strip().lower().encode()).hexdigest()
    cached = _nominatim_cache_get(cache_key)
    if cached is not None:
        return {**cached, "cached": True, "checked_at": checked_at}
    async with _nominatim_lock:
        # Enforce the 1 request/sec policy across the whole app.
        now = asyncio.get_running_loop().time()
        wait = NOMINATIM_MIN_INTERVAL - (now - _nominatim_last_call)
        if wait > 0:
            await asyncio.sleep(wait)
        try:
            async with _make_http_client(timeout=NOMINATIM_TIMEOUT) as client:
                resp = await client.get(
                    NOMINATIM_URL,
                    params={
                        "format": "jsonv2",
                        "q": address,
                        "addressdetails": "1",
                        "limit": "1",
                    },
                    headers={"User-Agent": NOMINATIM_USER_AGENT},
                )
                resp.raise_for_status()
                data = resp.json()
        except Exception as e:
            result = {
                **base,
                "reason": f"Nominatim request failed: {e}"[:500],
            }
            return result
        finally:
            _nominatim_last_call = asyncio.get_running_loop().time()
    results = data if isinstance(data, list) else []
    if not results:
        result = {
            **base, "status": "NONE",
            "reason": "Nominatim returned no match",
        }
        _nominatim_cache_put(cache_key, result)
        return result
    top = results[0] if isinstance(results[0], dict) else {}
    result = {
        **base,
        "status": "FOUND",
        "standardized_address": top.get("display_name"),
        "accuracy": top.get("importance"),
        "coordinates": {"lat": top.get("lat"), "lon": top.get("lon")},
        "osm_type": top.get("type"),
        "osm_class": top.get("class"),
    }
    _nominatim_cache_put(cache_key, result)
    return result


# ---------------------------------------------------------------------------
# Scan implementations
# ---------------------------------------------------------------------------
async def scan_phone(number):
    """Phone check: phonenumbers parse + PhoneInfoga v2 + known-scam lookup."""
    detail = {}
    # Local parse (no network) — carrier / region / validity.
    try:
        parsed = phonenumbers.parse(number, None)
        detail["parsed"] = {
            "e164": phonenumbers.format_number(
                parsed, phonenumbers.PhoneNumberFormat.E164
            ),
            "country_code": parsed.country_code,
            "national_number": str(parsed.national_number),
            "possible": phonenumbers.is_possible_number(parsed),
            "valid": phonenumbers.is_valid_number(parsed),
            "region": pn_geocoder.description_for_number(parsed, "en"),
            "carrier": pn_carrier.name_for_number(parsed, "en"),
            "number_type": str(
                phonenumbers.number_type(parsed)).split(".")[-1],
        }
    except Exception as e:
        detail["parsed"] = {"error": str(e)}

    # PhoneInfoga v2 (Go binary, arg-list, timeout). Its numverify
    # scanner is disabled (-D numverify): it calls the dead endpoint
    # https://api.apilayer.com/number_verification/validate (Cloudflare
    # 504, misreported as "Invalid authentication credentials"). The
    # other scanners (googlesearch etc.) still run. Carrier/line-type
    # comes from a direct Numverify API call below instead.
    pi_output, pi_ok = await run_cmd_async(
        [PHONEINFOGA_BIN, "scan", "-n", number, "-D", "numverify"],
        PHONEINFOGA_TIMEOUT,
    )
    detail["phoneinfoga"] = {
        "ran": pi_ok,
        "output": pi_output[:8000],
    }
    # Numverify direct call (working endpoint). The number is passed in
    # E.164 when the local parse produced one, else the raw target.
    nv_number = (detail.get("parsed") or {}).get("e164") or number
    detail["numverify"] = await numverify_lookup(nv_number)

    # Known-scam lookup.
    verified = await supabase_lookup_verified(number, "phone")
    detail["known_scam"] = verified is not None
    detail["verified_scam"] = verified

    parsed = detail.get("parsed", {})
    summary_bits = []
    if parsed.get("valid"):
        summary_bits.append("valid number")
    elif parsed.get("possible"):
        summary_bits.append("possible number")
    else:
        summary_bits.append("not a valid number")
    if parsed.get("carrier"):
        summary_bits.append(f"carrier: {parsed['carrier']}")
    if parsed.get("region"):
        summary_bits.append(f"region: {parsed['region']}")
    if verified:
        summary_bits.append("KNOWN SCAM — in verified_scams")
    summary = "; ".join(summary_bits) if summary_bits else "phone check done"
    return summary, detail


async def scan_email(email):
    """Email check: format + domain MX (DoH) + user-scanner registration
    check (210+ sites) + known-scam lookup."""
    detail = {}
    local, _, domain = email.rpartition("@")
    detail["local_part"] = local
    detail["domain"] = domain
    mx = await doh_lookup(domain, "MX")
    a_records = await doh_lookup(domain, "A")
    detail["domain_mx"] = mx
    detail["domain_a"] = a_records
    detail["domain_has_mail"] = bool(mx)
    # user-scanner: is this email registered on public sites?
    # NEVER passes --hudson (infostealer corpus — prohibited).
    detail["user_scanner"] = await run_user_scanner(email, "email")
    verified = await supabase_lookup_verified(email, "email")
    verified_domain = None
    if not verified:
        verified_domain = await supabase_lookup_verified(domain, "domain")
    detail["known_scam"] = verified is not None
    detail["verified_scam"] = verified
    detail["verified_scam_domain"] = verified_domain
    summary_bits = []
    summary_bits.append("domain accepts mail" if mx else "domain has no MX record")
    us = detail["user_scanner"]
    if us["status"] == "FOUND":
        summary_bits.append(
            f"registered on {us['registered_count']} site(s) via user-scanner"
        )
    elif us["status"] == "NONE":
        summary_bits.append("not registered on any checked site (user-scanner)")
    elif us["status"] == "SKIP":
        summary_bits.append("user-scanner skipped (not installed)")
    elif us["status"] == "ERR":
        summary_bits.append("user-scanner could not determine registration")
    if verified:
        summary_bits.append("KNOWN SCAM — email in verified_scams")
    elif verified_domain:
        summary_bits.append("KNOWN SCAM — domain in verified_scams")
    summary = "; ".join(summary_bits)
    return summary, detail


async def scan_domain(domain):
    """Domain check: DNS (DoH A/MX/TXT) + RDAP + subfinder subdomain
    enumeration + crt.sh certificate-transparency subdomains +
    known-scam lookup."""
    detail = {}
    a_records = await doh_lookup(domain, "A")
    mx = await doh_lookup(domain, "MX")
    txt = await doh_lookup(domain, "TXT")
    detail["dns_a"] = a_records
    detail["dns_mx"] = mx
    detail["dns_txt"] = txt
    rdap = await rdap_lookup(domain)
    detail["rdap"] = rdap
    # Subdomain enumeration: subfinder (passive sources, keyless only)
    # plus a direct crt.sh query (certificate transparency). Each is
    # recorded separately with its own status and provenance; the merged
    # list is the union.
    detail["subfinder"] = await run_subfinder(domain)
    detail["crtsh"] = await crtsh_lookup(domain)
    merged = set(detail["subfinder"].get("subdomains", [])) | set(
        detail["crtsh"].get("subdomains", [])
    )
    detail["subdomains"] = sorted(merged)
    detail["subdomain_count"] = len(merged)
    verified = await supabase_lookup_verified(domain, "domain")
    detail["known_scam"] = verified is not None
    detail["verified_scam"] = verified
    summary_bits = []
    if a_records:
        summary_bits.append(f"resolves to {a_records[0]}")
    else:
        summary_bits.append("does not resolve (no A record)")
    if rdap and rdap.get("registrar"):
        summary_bits.append(f"registrar: {rdap['registrar']}")
    if merged:
        summary_bits.append(f"{len(merged)} subdomain(s) found")
    if verified:
        summary_bits.append("KNOWN SCAM — in verified_scams")
    summary = "; ".join(summary_bits)
    return summary, detail


async def scan_username(username):
    """Username check: Maigret (top-sites subset) + known-scam lookup."""
    detail = {}
    out_dir = "/tmp/maigret_reports"
    os.makedirs(out_dir, exist_ok=True)
    argv = [
        MAIGRET_BIN, username,
        "--top-sites", str(MAIGRET_TOP_SITES),
        "--json", "simple",
        "--folderoutput", out_dir,
    ]
    output, ok = await run_cmd_async(argv, MAIGRET_TIMEOUT)
    detail["maigret"] = {"ran": ok, "output": output[-6000:]}
    # Parse the JSON report Maigret wrote (report_<user>_simple.json).
    report_path = os.path.join(out_dir, f"report_{username}_simple.json")
    found = []
    try:
        with open(report_path) as f:
            report = json.load(f)
        for site, entry in (report or {}).items():
            if isinstance(entry, dict) and entry.get("status"):
                status = entry["status"]
                if status.get("found"):
                    found.append({
                        "site": site,
                        "url": status.get("url"),
                        "username": status.get("username"),
                    })
    except Exception:
        pass
    detail["found_accounts"] = found
    detail["found_count"] = len(found)
    verified = await supabase_lookup_verified(username, "username")
    detail["known_scam"] = verified is not None
    detail["verified_scam"] = verified
    summary = f"{len(found)} account(s) found across top {MAIGRET_TOP_SITES} sites"
    if verified:
        summary += "; KNOWN SCAM — in verified_scams"
    return summary, detail


async def verify_address(address):
    """Address verification: parse (usaddress) -> Geocodio (primary)
    -> Census Geocoder (fallback/second opinion) -> Nominatim (third
    opinion, only on disagreement or when both are unavailable).
    Returns (summary, detail). detail carries verdict (FOUND/NONE/
    SKIP/ERR), source, standardized_address, accuracy, accuracy_type,
    and every step with its own status and UTC timestamp.
    Verdict rules:
      Geocodio FOUND -> FOUND (source geocodio).
      Geocodio NONE -> NONE (flag), Census recorded as second opinion;
        Nominatim consulted only if Census FOUND (disagreement).
        A Census range match does NOT override Geocodio's
        deliverability answer — the disagreement itself is the flag.
      Geocodio SKIP/ERR -> Census decides: FOUND (weak, source
        census) / NONE / ERR (then Nominatim as last resort).
    A real API answer is a real verdict even if negative; a failed
    call is ERR, never a fake valid. A missing Geocodio key is SKIP
    at the step level — with the Census fallback live, the key alone
    never decides the final verdict."""
    detail = {}
    detail["parsed"] = parse_address(address)
    geo = await geocodio_lookup(address)
    detail["geocodio"] = geo
    census = None
    nominatim = {
        "tool": "nominatim",
        "status": "SKIP",
        "reason": "not needed — Geocodio decided the verdict",
        "checked_at": _utc_now(),
    }
    verdict = None
    source = None
    standardized = None
    accuracy = None
    accuracy_type = None
    weak = False

    if geo["status"] == "FOUND":
        verdict, source = "FOUND", "geocodio"
        standardized = geo.get("standardized_address")
        accuracy = geo.get("accuracy")
        accuracy_type = geo.get("accuracy_type")
        weak = bool(geo.get("weak"))
    else:
        # Geocodio did not decide (NONE, SKIP, or ERR) — Census speaks.
        census = await census_lookup(address)
        detail["census"] = census
        if geo["status"] == "NONE":
            # Geocodio gave a real answer: no street-level match.
            # A Census range match does not override a deliverability
            # check — it is recorded, and Nominatim is consulted as
            # the third opinion on the disagreement. Verdict stays
            # NONE (flag for review).
            verdict, source = "NONE", "geocodio"
            standardized = geo.get("standardized_address")
            accuracy = geo.get("accuracy")
            accuracy_type = geo.get("accuracy_type")
            if census["status"] == "FOUND":
                nominatim = await nominatim_lookup(address)
        elif census["status"] == "FOUND":
            verdict, source = "FOUND", "census"
            standardized = census.get("standardized_address")
            accuracy = None
            accuracy_type = "range"
            weak = True
        elif census["status"] == "NONE":
            verdict, source = "NONE", "census"
            standardized = None
            accuracy = None
            accuracy_type = None
        else:  # Census ERR and Geocodio SKIP/ERR: Nominatim last resort.
            nominatim = await nominatim_lookup(address)
            if nominatim["status"] == "FOUND":
                verdict, source = "FOUND", "nominatim"
                standardized = nominatim.get("standardized_address")
                accuracy = nominatim.get("accuracy")
                accuracy_type = "existence"
                weak = True
            elif nominatim["status"] == "NONE":
                verdict, source = "NONE", "nominatim"
            else:
                verdict, source = "ERR", None
    if census is None:
        detail["census"] = {
            "tool": "census",
            "status": "SKIP",
            "reason": "not needed — Geocodio decided the verdict",
            "checked_at": _utc_now(),
        }
    detail["nominatim"] = nominatim
    detail["verdict"] = verdict
    detail["source"] = source
    detail["standardized_address"] = standardized
    detail["accuracy"] = accuracy
    detail["accuracy_type"] = accuracy_type
    detail["weak"] = weak
    detail["checked_at"] = _utc_now()
    # Known-scam / known-good lookups (same pattern as the other scans).
    verified = await supabase_lookup_verified(standardized or address, "address")
    detail["known_scam"] = verified is not None
    detail["verified_scam"] = verified
    known_valid = await supabase_lookup_valid(standardized or address, "address")
    detail["known_valid"] = known_valid is not None
    detail["verified_valid"] = known_valid

    summary_bits = []
    if verdict == "FOUND":
        summary_bits.append(
            f"address verified via {source}"
            + (" (weak — range/existence only)" if weak else "")
        )
    elif verdict == "NONE":
        summary_bits.append(
            f"no street-level match (flag for review; source {source})"
        )
    elif verdict == "SKIP":
        summary_bits.append(
            "verification skipped (no Geocodio key and no fallback answer)"
        )
    else:
        summary_bits.append("verification failed (see step details)")
    if standardized:
        summary_bits.append(f"standardized: {standardized}")
    if accuracy is not None:
        summary_bits.append(f"accuracy: {accuracy} ({accuracy_type})")
    if verified:
        summary_bits.append("KNOWN SCAM — address in verified_scams")
    summary = "; ".join(summary_bits)
    return summary, detail


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.get("/health")
async def health():
    return {
        "status": "ok",
        "service": "scam-intel-api",
        "version": "3.0.0-phase1.3",
        "supabase_configured": _supabase_configured(),
    }


def _bad_request(message):
    return JSONResponse(status_code=400, content={"detail": message})


@app.post("/scan/phone")
async def api_scan_phone(request: Request, _auth: bool = Depends(require_token)):
    data = await request.json() if request.headers.get("content-type", "").startswith("application/json") else {}
    target = (data.get("target") or "").strip()
    if not target or not validate_target("phone", target):
        return _bad_request("Invalid phone number.")
    async with _scan_semaphore:
        summary, detail = await scan_phone(target)
    row = await supabase_insert_scan(
        "phoneinfoga", target, "phone", summary, detail, "complete"
    )
    return {
        "scan_id": row.get("id") if row else None,
        "tool": "phoneinfoga",
        "target": target,
        "target_type": "phone",
        "status": "complete",
        "result_summary": summary,
        "result": detail,
        "known_scam": detail.get("known_scam", False),
        "stored": row is not None,
    }


@app.post("/scan/email")
async def api_scan_email(request: Request, _auth: bool = Depends(require_token)):
    data = await request.json() if request.headers.get("content-type", "").startswith("application/json") else {}
    target = (data.get("target") or "").strip()
    if not target or not validate_target("email", target):
        return _bad_request("Invalid email address.")
    async with _scan_semaphore:
        summary, detail = await scan_email(target)
    row = await supabase_insert_scan(
        "email_check", target, "email", summary, detail, "complete"
    )
    return {
        "scan_id": row.get("id") if row else None,
        "tool": "email_check",
        "target": target,
        "target_type": "email",
        "status": "complete",
        "result_summary": summary,
        "result": detail,
        "known_scam": detail.get("known_scam", False),
        "stored": row is not None,
    }


@app.post("/scan/domain")
async def api_scan_domain(request: Request, _auth: bool = Depends(require_token)):
    data = await request.json() if request.headers.get("content-type", "").startswith("application/json") else {}
    target = (data.get("target") or "").strip().lower()
    if not target or not validate_target("domain", target):
        return _bad_request("Invalid domain.")
    async with _scan_semaphore:
        summary, detail = await scan_domain(target)
    row = await supabase_insert_scan(
        "domain_check", target, "domain", summary, detail, "complete"
    )
    return {
        "scan_id": row.get("id") if row else None,
        "tool": "domain_check",
        "target": target,
        "target_type": "domain",
        "status": "complete",
        "result_summary": summary,
        "result": detail,
        "known_scam": detail.get("known_scam", False),
        "stored": row is not None,
    }


@app.post("/scan/username")
async def api_scan_username(request: Request, _auth: bool = Depends(require_token)):
    data = await request.json() if request.headers.get("content-type", "").startswith("application/json") else {}
    target = (data.get("target") or "").strip()
    if not target or not validate_target("username", target):
        return _bad_request("Invalid username.")
    async with _scan_semaphore:
        summary, detail = await scan_username(target)
    row = await supabase_insert_scan(
        "maigret", target, "username", summary, detail, "complete"
    )
    return {
        "scan_id": row.get("id") if row else None,
        "tool": "maigret",
        "target": target,
        "target_type": "username",
        "status": "complete",
        "result_summary": summary,
        "result": detail,
        "known_scam": detail.get("known_scam", False),
        "stored": row is not None,
    }


@app.post("/address/verify")
async def api_address_verify(request: Request, _auth: bool = Depends(require_token)):
    data = await request.json() if request.headers.get("content-type", "").startswith("application/json") else {}
    target = (data.get("target") or "").strip()
    if not target or not validate_target("address", target):
        return _bad_request("Invalid address.")
    async with _scan_semaphore:
        summary, detail = await verify_address(target)
    # Target type for the scans row. The scans CHECK constraint does
    # not yet list 'address' (migration:
    # scans-add-address-type.sql, run in the Supabase SQL editor);
    # until it lands, address scans are stored as 'other' so the row
    # is never lost. After the migration, switch this back to
    # 'address' and backfill:
    #   UPDATE scans SET target_type='address'
    #   WHERE tool='address_check';
    row = await supabase_insert_scan(
        "address_check", target, "other", summary, detail, "complete"
    )
    # Verified-good addresses upsert into verified_valid (the good
    # list), keyed on the standardized address when available so
    # "123 Main St" and "123 Main Street" match. This complements
    # Stripe AVS/Radar — it does not replace it.
    valid_row = None
    if detail.get("verdict") == "FOUND":
        valid_target = detail.get("standardized_address") or target
        valid_row = await supabase_upsert_valid(
            valid_target, "address", detail.get("source"),
            detail,
            f"Address verified via {detail.get('source')}: "
            f"{detail.get('accuracy_type')} "
            f"(accuracy {detail.get('accuracy')})",
        )
    return {
        "scan_id": row.get("id") if row else None,
        "tool": "address_check",
        "target": target,
        "target_type": "address",
        "status": "complete",
        "result_summary": summary,
        "result": detail,
        "verdict": detail.get("verdict"),
        "source": detail.get("source"),
        "standardized_address": detail.get("standardized_address"),
        "accuracy": detail.get("accuracy"),
        "accuracy_type": detail.get("accuracy_type"),
        "known_scam": detail.get("known_scam", False),
        "known_valid": detail.get("known_valid", False),
        "stored": row is not None,
        "verified_valid_id": valid_row.get("id") if valid_row else None,
    }


@app.post("/scam/report")
async def api_scam_report(request: Request, _auth: bool = Depends(require_token)):
    data = await request.json() if request.headers.get("content-type", "").startswith("application/json") else {}
    target = (data.get("target") or "").strip()
    target_type = (data.get("target_type") or "").strip().lower()
    evidence = (data.get("evidence") or "").strip()
    if target_type not in ("phone", "domain", "email", "other"):
        return _bad_request("target_type must be phone, domain, email, or other.")
    kind = "phone" if target_type == "phone" else (
        "email" if target_type == "email" else (
            "domain" if target_type == "domain" else "other"))
    if kind != "other" and not validate_target(kind, target):
        return _bad_request(f"Invalid {target_type} target.")
    if kind == "other" and (not target or len(target) > 253):
        return _bad_request("Invalid target.")
    if len(evidence) > 4000:
        return _bad_request("Evidence is too long (max 4000 characters).")
    row = await supabase_upsert_verified(target, target_type, evidence)
    if row is None:
        raise HTTPException(status_code=502, detail="Could not write to Supabase.")
    return {
        "target": row.get("target"),
        "target_type": row.get("target_type"),
        "evidence": row.get("evidence"),
        "reporter_count": row.get("reporter_count"),
        "first_seen": row.get("first_seen"),
        "last_seen": row.get("last_seen"),
        "id": row.get("id"),
    }


@app.get("/scam/check")
async def api_scam_check(
    target: str = Query(..., min_length=1, max_length=253),
    _auth: bool = Depends(require_token),
):
    target = target.strip()
    row = await supabase_lookup_verified(target)
    if row:
        return {
            "target": target,
            "known_scam": True,
            "verified_scam": row,
        }
    return {"target": target, "known_scam": False, "verified_scam": None}


if __name__ == "__main__":
    import uvicorn

    print("\n  Scam Intel API v3.0 — Phase 1 backend")
    if TOKEN_WAS_GENERATED:
        print("  [!] No SCAMINTEL_API_TOKEN set — using a random token:")
        print(f"      {API_TOKEN}")
        print("  Set SCAMINTEL_API_TOKEN in the environment for a stable token.\n")
    if not _supabase_configured():
        print("  [!] SUPABASE_URL / SUPABASE_SERVICE_KEY not set — scans will")
        print("      run but rows will NOT be stored in Supabase.\n")
    print(f"  Listening on http://127.0.0.1:{PORT}\n")
    uvicorn.run(app, host="127.0.0.1", port=PORT, log_level="info")
