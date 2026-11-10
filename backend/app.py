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

Tools (per ARCHITECTURE.md §2):
  - PhoneInfoga v2 (Go binary) — phone/carrier/VOIP lookups.
  - Maigret — username checks (top-sites subset; full 509-site run is
    too slow for a synchronous API call).
  - phonenumbers lib — phone parsing/validation/carrier.
  - DNS over HTTPS (Google/Cloudflare DoH) — real DNS. The local system
    resolver in this VM returns synthetic proxy addresses, so DoH is used.
  - RDAP over HTTPS (rdap.org) — registrar/status/creation data.
    Direct WHOIS (port 43) is blocked in this environment, so RDAP is
    the WHOIS replacement.
  - Holehe and Sherlock are DROPPED (deprecated/rotted) — not used.

Run:
  SCAMINTEL_API_TOKEN=<token> SUPABASE_URL=<url> \\
  SUPABASE_SERVICE_KEY=<service_role_key> ./run.sh
"""

import asyncio
import json
import os
import re
import secrets
import subprocess
import urllib.parse

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

# Tool paths / tunables (env-overridable, sane defaults).
PHONEINFOGA_BIN = os.environ.get(
    "PHONEINFOGA_BIN",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "tools", "phoneinfoga"),
)
MAIGRET_BIN = os.environ.get("MAIGRET_BIN", "maigret")
MAIGRET_TOP_SITES = int(os.environ.get("MAIGRET_TOP_SITES", "50"))
MAIGRET_TIMEOUT = int(os.environ.get("MAIGRET_TIMEOUT", "180"))
PHONEINFOGA_TIMEOUT = int(os.environ.get("PHONEINFOGA_TIMEOUT", "90"))
HTTP_TIMEOUT = float(os.environ.get("HTTP_TIMEOUT", "15"))
MAX_CONCURRENT_SCANS = int(os.environ.get("MAX_CONCURRENT_SCANS", "3"))

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
    return False


# ---------------------------------------------------------------------------
# App + auth
# ---------------------------------------------------------------------------
app = FastAPI(
    title="Scam Intel API",
    version="3.0.0-phase1",
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
    without it they cannot leave this VM."""
    proxy = (
        os.environ.get("https_proxy")
        or os.environ.get("HTTPS_PROXY")
        or os.environ.get("http_proxy")
        or os.environ.get("HTTP_PROXY")
    )
    return httpx.AsyncClient(timeout=timeout, trust_env=False, proxy=proxy)


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


# ---------------------------------------------------------------------------
# Tool runners (subprocess arg-lists ONLY — never shell=True)
# ---------------------------------------------------------------------------
def run_cmd(argv, timeout):
    """Run a command given as an argument LIST. Returns (output, ok).
    Never a shell string."""
    if not isinstance(argv, (list, tuple)) or not argv:
        return "[ERROR] Invalid command.", False
    try:
        result = subprocess.run(
            list(argv), shell=False, capture_output=True, text=True,
            timeout=timeout,
        )
        return (result.stdout + result.stderr), result.returncode == 0
    except subprocess.TimeoutExpired:
        return "[TIMEOUT] Command took too long.", False
    except FileNotFoundError:
        return f"[ERROR] Tool not installed: {argv[0]}", False
    except Exception as e:
        return f"[ERROR] {str(e)}", False


async def run_cmd_async(argv, timeout):
    """Run run_cmd in a thread so the event loop is not blocked."""
    return await asyncio.to_thread(run_cmd, argv, timeout)


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

    # PhoneInfoga v2 (Go binary, arg-list, timeout).
    pi_output, pi_ok = await run_cmd_async(
        [PHONEINFOGA_BIN, "scan", "-n", number], PHONEINFOGA_TIMEOUT
    )
    detail["phoneinfoga"] = {
        "ran": pi_ok,
        "output": pi_output[:8000],
    }

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
    """Email check: format + domain MX (DoH) + known-scam lookup."""
    detail = {}
    local, _, domain = email.rpartition("@")
    detail["local_part"] = local
    detail["domain"] = domain
    mx = await doh_lookup(domain, "MX")
    a_records = await doh_lookup(domain, "A")
    detail["domain_mx"] = mx
    detail["domain_a"] = a_records
    detail["domain_has_mail"] = bool(mx)
    verified = await supabase_lookup_verified(email, "email")
    verified_domain = None
    if not verified:
        verified_domain = await supabase_lookup_verified(domain, "domain")
    detail["known_scam"] = verified is not None
    detail["verified_scam"] = verified
    detail["verified_scam_domain"] = verified_domain
    summary_bits = []
    summary_bits.append("domain accepts mail" if mx else "domain has no MX record")
    if verified:
        summary_bits.append("KNOWN SCAM — email in verified_scams")
    elif verified_domain:
        summary_bits.append("KNOWN SCAM — domain in verified_scams")
    summary = "; ".join(summary_bits)
    return summary, detail


async def scan_domain(domain):
    """Domain check: DNS (DoH A/MX/TXT) + RDAP + known-scam lookup."""
    detail = {}
    a_records = await doh_lookup(domain, "A")
    mx = await doh_lookup(domain, "MX")
    txt = await doh_lookup(domain, "TXT")
    detail["dns_a"] = a_records
    detail["dns_mx"] = mx
    detail["dns_txt"] = txt
    rdap = await rdap_lookup(domain)
    detail["rdap"] = rdap
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


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.get("/health")
async def health():
    return {
        "status": "ok",
        "service": "scam-intel-api",
        "version": "3.0.0-phase1",
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
