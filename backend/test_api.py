#!/usr/bin/env python3
"""
Scam Intel API — validation test battery (Phase 1).
Same approach as Phase 0: input-validation cases, path-traversal cases,
auth cases, plus a live exercise of every endpoint against a running
service (including a real write to the `scans` table with synthetic
test targets only — fictional 555 numbers, example.com, test usernames).

Usage:
  SCAMINTEL_API_TOKEN=<token> python3 test_api.py [base_url]
  Default base_url: http://127.0.0.1:8000

Exit code 0 when every case passes, 1 otherwise.
"""
import json
import os
import sys

import httpx

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"
TOKEN = os.environ.get("SCAMINTEL_API_TOKEN", "")
WRONG_TOKEN = "definitely-not-the-token"

RESULTS = []
SKIPPED = []


def check(name, ok, detail=""):
    RESULTS.append((name, bool(ok), detail))
    mark = "PASS" if ok else "FAIL"
    print(f"[{mark}] {name}" + (f" — {detail}" if detail else ""))


def skip(reason, names):
    """Record checks as SKIPPED (not failed) — used when the number-log
    tables do not exist yet (DDL not run). The run still exits 0 when
    every non-skipped check passes."""
    for name in names:
        SKIPPED.append((name, reason))
        print(f"[SKIP] {name} — {reason}")


def auth_headers(token=None):
    return {"Authorization": f"Bearer {token if token is not None else TOKEN}"}


def main():
    # Remote base URLs (e.g. live Render) need the egress proxy;
    # localhost needs none. The runtime's NO_PROXY list breaks httpx
    # parsing, so trust_env stays False and the proxy is passed
    # explicitly when the target is not local.
    _proxy = None
    if "127.0.0.1" not in BASE and "localhost" not in BASE:
        _proxy = (
            os.environ.get("https_proxy")
            or os.environ.get("HTTPS_PROXY")
            or os.environ.get("http_proxy")
            or os.environ.get("HTTP_PROXY")
        )
    client = httpx.Client(base_url=BASE, timeout=300, trust_env=False,
                          proxy=_proxy)

    # Cleanup: the battery's own synthetic verified_scams row
    # (+15559876543) persists between runs — delete it up front so
    # repeated runs are idempotent ("check unknown" and the
    # reporter_count assertions assume a clean table). Uses the same
    # Supabase service credentials the server uses; skipped silently
    # when they are not in the test environment. Needs the egress
    # proxy explicitly (this VM cannot reach Supabase directly).
    _sb_url = os.environ.get("SUPABASE_URL", "").rstrip("/")
    _sb_key = os.environ.get("SUPABASE_SERVICE_KEY", "")
    _proxy = (
        os.environ.get("https_proxy")
        or os.environ.get("HTTPS_PROXY")
        or os.environ.get("http_proxy")
        or os.environ.get("HTTP_PROXY")
    )
    if _sb_url and _sb_key:
        try:
            _sb_client = httpx.Client(
                timeout=30, trust_env=False, proxy=_proxy
            )
            _sb_client.delete(
                f"{_sb_url}/rest/v1/verified_scams",
                params={"target": "eq.+15559876543"},
                headers={"apikey": _sb_key,
                         "Authorization": f"Bearer {_sb_key}"},
            )
            # Number-log test rows (fictional 555-01xx) from any prior
            # run, in both tables, so repeated runs are idempotent.
            for _table in ("verified_numbers", "questionable_numbers"):
                _sb_client.delete(
                    f"{_sb_url}/rest/v1/{_table}",
                    params={"number_e164": "ilike.+155501%"},
                    headers={"apikey": _sb_key,
                             "Authorization": f"Bearer {_sb_key}"},
                )
            _sb_client.close()
        except Exception:
            pass

    # --- Health (no auth) ---
    r = client.get("/health")
    check("health returns 200", r.status_code == 200, f"got {r.status_code}")
    check("health supabase_configured", r.json().get("supabase_configured") is True)

    # --- Auth ---
    r = client.post("/scan/phone", json={"target": "+15551234567"})
    check("no token -> 401", r.status_code == 401, f"got {r.status_code}")
    r = client.post("/scan/phone", json={"target": "+15551234567"},
                    headers=auth_headers(WRONG_TOKEN))
    check("wrong token -> 401", r.status_code == 401, f"got {r.status_code}")
    r = client.get("/scam/check", params={"target": "nobody@example.com"},
                   headers=auth_headers(WRONG_TOKEN))
    check("wrong token on check -> 401", r.status_code == 401, f"got {r.status_code}")
    r = client.post("/address/verify",
                    json={"target": "1600 Amphitheatre Parkway, Mountain View, CA 94043"})
    check("no token on address verify -> 401", r.status_code == 401, f"got {r.status_code}")
    r = client.post("/address/verify",
                    json={"target": "1600 Amphitheatre Parkway, Mountain View, CA 94043"},
                    headers=auth_headers(WRONG_TOKEN))
    check("wrong token on address verify -> 401", r.status_code == 401, f"got {r.status_code}")

    # --- Input validation (expect 400) ---
    bad_cases = [
        ("phone", "not-a-phone"),
        ("phone", "+15551234567; rm -rf /"),
        ("phone", "+15551234567$(whoami)"),
        ("phone", ""),
        ("phone", "x" * 100),
        ("email", "not-an-email"),
        ("email", "a@b"),
        ("email", "user@example.com; cat /etc/passwd"),
        ("email", "x" * 200 + "@example.com"),
        ("domain", "not a domain"),
        ("domain", "example.com/../../etc/passwd"),
        ("domain", "-bad-.com"),
        ("domain", "example.com; whoami"),
        ("username", "bad user!"),
        ("username", "../etc/passwd"),
        ("username", "user; rm -rf /"),
        ("username", "x" * 100),
    ]
    for kind, target in bad_cases:
        r = client.post(f"/scan/{kind}", json={"target": target},
                        headers=auth_headers())
        # The path-traversal payload may be rejected at the edge (403
        # from Cloudflare's WAF on hosted deployments) instead of by
        # the app (400) — either way it is rejected, never executed.
        want = (400, 403) if "../" in target else (400,)
        check(f"invalid {kind} {target[:30]!r} -> rejected",
              r.status_code in want, f"got {r.status_code}")

    # Path traversal / injection as a target value (must not execute).
    r = client.post("/scan/domain", json={"target": "example.com`id`"},
                    headers=auth_headers())
    check("backtick injection -> 400", r.status_code == 400, f"got {r.status_code}")
    r = client.post("/scan/phone", json={"target": "+1 (555) 123-4567 && id"},
                    headers=auth_headers())
    check("shell metachars in phone -> 400", r.status_code == 400, f"got {r.status_code}")

    # Address validation (expect 400).
    for bad_addr in ["", "1600 Main St; rm -rf /", "1600 Main St $(whoami)",
                     "x" * 300, "!!!", "1600 Main St `id`"]:
        r = client.post("/address/verify", json={"target": bad_addr},
                        headers=auth_headers())
        check(f"invalid address {bad_addr[:30]!r} -> 400",
              r.status_code == 400, f"got {r.status_code}")

    # --- Live scans (synthetic targets only) ---
    # Phone (fictional 555 number).
    r = client.post("/scan/phone", json={"target": "+15551234567"},
                    headers=auth_headers())
    ok = r.status_code == 200
    body = r.json() if ok else {}
    check("phone scan 200", ok, f"got {r.status_code}")
    check("phone scan stored in scans", body.get("stored") is True,
          f"scan_id={body.get('scan_id')}")
    check("phone scan known_scam false", body.get("known_scam") is False)
    check("phone scan has parsed result",
          isinstance(body.get("result", {}).get("parsed"), dict))
    # numverify step: direct Numverify API call (Phase 1.2 fix — the
    # backend calls https://api.apilayer.net/numverify/api/validate
    # directly; PhoneInfoga's built-in numverify scanner hits a dead
    # endpoint and misreports it as "Invalid authentication
    # credentials"). Present with a valid status. Without a key it must
    # be SKIP (never a fake clean); with a key it must be ran/ERR.
    # NUMVERIFY_EXPECTED (env) pins the expected status for this run:
    #   SKIP = server started without a key
    #   ERR  = server started with an invalid key
    #   ran  = server started with a valid key (live Render)
    nv = body.get("result", {}).get("numverify", {})
    check("phone scan numverify present", bool(nv),
          f"keys={list(body.get('result', {}).keys())}")
    check("phone scan numverify status valid",
          nv.get("status") in ("SKIP", "ran", "ERR"),
          f"status={nv.get('status')} enabled={nv.get('enabled')}")
    expected_nv = os.environ.get("NUMVERIFY_EXPECTED", "").strip()
    if expected_nv:
        check(f"phone scan numverify status is {expected_nv}",
              nv.get("status") == expected_nv,
              f"status={nv.get('status')} enabled={nv.get('enabled')}")
    if nv.get("status") == "ran":
        # Real API fields must be present; the old failure mode
        # ("Invalid authentication credentials") must never appear.
        check("phone scan numverify ran has real API fields",
              all(k in nv for k in ("valid", "country_code", "carrier", "line_type")),
              f"valid={nv.get('valid')} country={nv.get('country_code')} carrier={nv.get('carrier')!r} line_type={nv.get('line_type')!r}")
        check("phone scan numverify ran is not the auth failure",
              "Invalid authentication credentials" not in str(nv.get("output", "")),
              f"output={str(nv.get('output', ''))[:120]}")
        check("phone scan numverify ran has checked_at",
              bool(nv.get("checked_at")))
    elif nv.get("status") == "ERR":
        # An invalid key must be ERR, never a fake "valid" result.
        check("phone scan numverify ERR claims no valid data",
              nv.get("valid") is not True
              and "valid: true" not in str(nv.get("output", "")).lower(),
              f"status={nv.get('status')} reason={str(nv.get('reason', ''))[:120]}")
    elif nv.get("status") == "SKIP":
        check("phone scan numverify SKIP without key",
              nv.get("enabled") is False and nv.get("status") == "SKIP",
              f"status={nv.get('status')}")
        # SKIP has two causes: the NUMVERIFY_ENABLED gate is off
        # (Phase 1.4 default — quota preserved) or no key is set.
        # Either way the reason must say which one it is.
        check("phone scan numverify SKIP reason names the cause",
              "NUMVERIFY_ENABLED" in str(nv.get("reason", ""))
              or "NUMVERIFY_API_KEY not set" in str(nv.get("reason", "")),
              f"reason={str(nv.get('reason', ''))[:120]}")

    # Email.
    r = client.post("/scan/email", json={"target": "test@example.com"},
                    headers=auth_headers())
    ok = r.status_code == 200
    body = r.json() if ok else {}
    check("email scan 200", ok, f"got {r.status_code}")
    check("email scan stored", body.get("stored") is True,
          f"scan_id={body.get('scan_id')}")
    check("email scan domain_mx present",
          "domain_mx" in body.get("result", {}))
    # user-scanner step (email registration check, 210+ sites).
    us = body.get("result", {}).get("user_scanner", {})
    check("email scan user_scanner present", bool(us),
          f"keys={list(body.get('result', {}).keys())}")
    check("email scan user_scanner status valid",
          us.get("status") in ("FOUND", "NONE", "SKIP", "ERR"),
          f"status={us.get('status')}")
    check("email scan user_scanner has counts",
          "registered_count" in us and "total_modules" in us,
          f"registered={us.get('registered_count')} total={us.get('total_modules')}")
    check("email scan user_scanner has checked_at",
          bool(us.get("checked_at")))
    # The scan must never claim a fake clean: if it says NONE, at least
    # one module gave a definitive not-registered answer.
    if us.get("status") == "NONE":
        check("email NONE has a definitive not-registered module",
              us.get("not_registered_count", 0) > 0,
              f"not_registered={us.get('not_registered_count')}")

    # Domain.
    r = client.post("/scan/domain", json={"target": "example.com"},
                    headers=auth_headers())
    ok = r.status_code == 200
    body = r.json() if ok else {}
    check("domain scan 200", ok, f"got {r.status_code}")
    check("domain scan stored", body.get("stored") is True,
          f"scan_id={body.get('scan_id')}")
    check("domain scan dns_a present", "dns_a" in body.get("result", {}))
    check("domain scan rdap present", "rdap" in body.get("result", {}))
    # subfinder + crt.sh subdomain steps.
    sf = body.get("result", {}).get("subfinder", {})
    check("domain scan subfinder present", bool(sf),
          f"keys={list(body.get('result', {}).keys())}")
    check("domain scan subfinder status valid",
          sf.get("status") in ("FOUND", "NONE", "SKIP", "ERR"),
          f"status={sf.get('status')}")
    check("domain scan subfinder has checked_at", bool(sf.get("checked_at")))
    ct = body.get("result", {}).get("crtsh", {})
    check("domain scan crtsh present", bool(ct))
    check("domain scan crtsh status valid",
          ct.get("status") in ("FOUND", "NONE", "ERR"),
          f"status={ct.get('status')}")
    check("domain scan subdomains list present",
          isinstance(body.get("result", {}).get("subdomains"), list))
    check("domain scan subdomain_count present",
          "subdomain_count" in body.get("result", {}))

    # Username (slow — Maigret top-50, ~1-2 min).
    r = client.post("/scan/username", json={"target": "testuser12345"},
                    headers=auth_headers())
    ok = r.status_code == 200
    body = r.json() if ok else {}
    check("username scan 200", ok, f"got {r.status_code}")
    check("username scan stored", body.get("stored") is True,
          f"scan_id={body.get('scan_id')}")
    check("username scan found_count present",
          "found_count" in body.get("result", {}))

    # Address verification (fictional-but-real-format address + a fake
    # one). Geocodio step: no key -> SKIP (never fake clean); bad key
    # -> ERR; valid key -> FOUND/NONE on a real answer. Census is the
    # no-key fallback; Nominatim only runs on Geocodio/Census
    # disagreement. ADDRESS_EXPECTED (env) pins the verdict for this
    # run (FOUND on live Render with a key; FOUND locally via Census).
    r = client.post("/address/verify",
                    json={"target": "1600 Amphitheatre Parkway, Mountain View, CA 94043"},
                    headers=auth_headers())
    ok = r.status_code == 200
    body = r.json() if ok else {}
    check("address scan 200", ok, f"got {r.status_code}")
    check("address scan stored", body.get("stored") is True,
          f"scan_id={body.get('scan_id')}")
    check("address scan verdict valid",
          body.get("verdict") in ("FOUND", "NONE", "SKIP", "ERR"),
          f"verdict={body.get('verdict')} source={body.get('source')}")
    res = body.get("result", {})
    check("address scan result has steps",
          all(k in res for k in ("parsed", "geocodio", "census", "nominatim",
                                 "verdict", "source", "checked_at")),
          f"keys={list(res.keys())}")
    check("address scan geocodio status valid",
          res.get("geocodio", {}).get("status") in ("FOUND", "NONE", "SKIP", "ERR"),
          f"status={res.get('geocodio', {}).get('status')}")
    check("address scan census status valid",
          res.get("census", {}).get("status") in ("FOUND", "NONE", "SKIP", "ERR"),
          f"status={res.get('census', {}).get('status')}")
    check("address scan nominatim status valid",
          res.get("nominatim", {}).get("status") in ("FOUND", "NONE", "SKIP", "ERR"),
          f"status={res.get('nominatim', {}).get('status')}")
    check("address scan parsed present", "components" in res.get("parsed", {}),
          f"parseable={res.get('parsed', {}).get('parseable')}")
    check("address scan has checked_at", bool(res.get("checked_at")))
    expected_addr = os.environ.get("ADDRESS_EXPECTED", "").strip()
    if expected_addr:
        check(f"address scan verdict is {expected_addr}",
              body.get("verdict") == expected_addr,
              f"verdict={body.get('verdict')} source={body.get('source')}")
    if body.get("verdict") == "FOUND":
        check("address FOUND has standardized address",
              bool(body.get("standardized_address")),
              f"std={body.get('standardized_address')!r}")
        # Verified-good address upserts into verified_valid.
        if _sb_url and _sb_key:
            try:
                _sb_client = httpx.Client(timeout=30, trust_env=False,
                                          proxy=_proxy)
                vr = _sb_client.get(
                    f"{_sb_url}/rest/v1/verified_valid",
                    params={"target": f"eq.{body.get('standardized_address')}",
                            "target_type": "eq.address"},
                    headers={"apikey": _sb_key,
                             "Authorization": f"Bearer {_sb_key}"},
                )
                rows = vr.json() if vr.status_code == 200 else []
                check("address FOUND upserted into verified_valid",
                      len(rows) >= 1,
                      f"rows={len(rows)} std={body.get('standardized_address')!r}")
                _sb_client.close()
            except Exception as e:
                check("address FOUND upserted into verified_valid", False,
                      f"lookup failed: {e}")
    # Fake address: never FOUND.
    r = client.post("/address/verify",
                    json={"target": "99999 Nowhere Street, Faketown, ZZ 00000"},
                    headers=auth_headers())
    ok = r.status_code == 200
    body = r.json() if ok else {}
    check("fake address scan 200", ok, f"got {r.status_code}")
    check("fake address verdict never FOUND",
          body.get("verdict") in ("NONE", "ERR"),
          f"verdict={body.get('verdict')} source={body.get('source')}")
    check("fake address not in verified_valid",
          body.get("known_valid") is False,
          f"known_valid={body.get('known_valid')}")

    # --- /scam/check (unknown target) ---
    r = client.get("/scam/check", params={"target": "+15559876543"},
                   headers=auth_headers())
    body = r.json()
    check("check unknown -> known_scam false",
          r.status_code == 200 and body.get("known_scam") is False,
          f"got {r.status_code} {body.get('known_scam')}")

    # --- /scam/report (synthetic) then check finds it ---
    r = client.post("/scam/report",
                    json={"target": "+15559876543", "target_type": "phone",
                          "evidence": "[TEST] synthetic report for validation battery"},
                    headers=auth_headers())
    ok = r.status_code == 200
    body = r.json() if ok else {}
    check("report synthetic phone 200", ok, f"got {r.status_code}")
    check("report reporter_count 1", body.get("reporter_count") == 1,
          f"got {body.get('reporter_count')}")
    r = client.get("/scam/check", params={"target": "+15559876543"},
                   headers=auth_headers())
    body = r.json()
    check("check after report -> known_scam true",
          body.get("known_scam") is True)
    # Second report increments reporter_count.
    r = client.post("/scam/report",
                    json={"target": "+15559876543", "target_type": "phone",
                          "evidence": "[TEST] second report"},
                    headers=auth_headers())
    body = r.json()
    check("second report reporter_count 2", body.get("reporter_count") == 2,
          f"got {body.get('reporter_count')}")

    # --- /scam/report validation ---
    r = client.post("/scam/report",
                    json={"target": "x", "target_type": "bogus"},
                    headers=auth_headers())
    check("report bad target_type -> 400", r.status_code == 400, f"got {r.status_code}")
    r = client.post("/scam/report",
                    json={"target": "not-a-phone", "target_type": "phone"},
                    headers=auth_headers())
    check("report bad phone target -> 400", r.status_code == 400, f"got {r.status_code}")
    r = client.post("/scam/report",
                    json={"target": "example.com", "target_type": "domain",
                          "evidence": "x" * 5000},
                    headers=auth_headers())
    check("report evidence too long -> 400", r.status_code == 400, f"got {r.status_code}")

    # --- Phone Number Module (Phase 1.4) ---
    # All test numbers are the reserved fictional 555-0100..0199 block.
    # Auth on the new endpoints.
    r = client.post("/number/log", json={"target": "+15550101"})
    check("no token on number log -> 401", r.status_code == 401, f"got {r.status_code}")
    r = client.post("/number/verify",
                    json={"target": "+15550101", "person_name": "Test Person",
                          "source_doc": "test doc"})
    check("no token on number verify -> 401", r.status_code == 401, f"got {r.status_code}")
    r = client.get("/number/check", params={"target": "+15550101"})
    check("no token on number check -> 401", r.status_code == 401, f"got {r.status_code}")
    r = client.post("/number/log", json={"target": "+15550101"},
                    headers=auth_headers(WRONG_TOKEN))
    check("wrong token on number log -> 401", r.status_code == 401, f"got {r.status_code}")

    # Validation (no DB needed — these pass even before the DDL runs).
    r = client.post("/number/log", json={"target": "not-a-phone"},
                    headers=auth_headers())
    check("number log bad phone -> 400", r.status_code == 400, f"got {r.status_code}")
    r = client.post("/number/log",
                    json={"target": "+15550101", "channel": "pigeon"},
                    headers=auth_headers())
    check("number log bad channel -> 400", r.status_code == 400, f"got {r.status_code}")
    r = client.post("/number/log",
                    json={"target": "+15550101", "evidence_class": "Z"},
                    headers=auth_headers())
    check("number log bad evidence class -> 400", r.status_code == 400, f"got {r.status_code}")
    r = client.post("/number/log",
                    json={"target": "+15550101", "criteria_codes": ["NOPE-99"]},
                    headers=auth_headers())
    check("number log unknown criteria code -> 400", r.status_code == 400, f"got {r.status_code}")
    r = client.post("/number/log",
                    json={"target": "+15550101", "pattern_tags": ["not_a_tag"]},
                    headers=auth_headers())
    check("number log unknown pattern tag -> 400", r.status_code == 400, f"got {r.status_code}")
    r = client.post("/number/log",
                    json={"target": "+15550101", "exchange_count": "many"},
                    headers=auth_headers())
    check("number log bad exchange_count -> 400", r.status_code == 400, f"got {r.status_code}")
    r = client.post("/number/verify",
                    json={"target": "+15550102", "person_name": "Test Person"},
                    headers=auth_headers())
    check("number verify missing source_doc -> 400", r.status_code == 400, f"got {r.status_code}")
    r = client.post("/number/verify",
                    json={"target": "+15550102", "source_doc": "test doc"},
                    headers=auth_headers())
    check("number verify missing person_name -> 400", r.status_code == 400, f"got {r.status_code}")
    r = client.get("/number/check", params={"target": "not-a-phone"},
                   headers=auth_headers())
    check("number check bad phone -> 400", r.status_code == 400, f"got {r.status_code}")

    # DB-dependent checks. If the number-log tables do not exist yet
    # (DDL number-log-two-tables.sql not run in the Supabase SQL
    # editor), the first log returns 502 with that detail — the checks
    # below are SKIPPED, not failed. Re-run after the DDL for a full pass.
    _number_db_checks = [
        "number log 200", "number log table questionable",
        "number log standing observed",
        "number log credit -2.5 (PH-06 w5 B)",
        "number log created", "number log contact_count 1",
        "number log repeat 200", "number log repeat same id",
        "number log repeat contact_count 2",
        "number log repeat evidence class stays B",
        "number log repeat criteria merged",
        "number log repeat credit -4.0 (only new criterion added)",
        "number log confirmation credit +2.0 (PH-03 w2 A)",
        "number log neutral credit 0.0 (PH-01 w1 A)",
        "number log B over 12 exchanges credit -1.25",
        "number log C credit -1.25 (PH-06 w5 C)",
        "number verify flow log 200",
        "number verify without doc/person refused (already checked above)",
        "number verify promotion 200",
        "number verify promoted true",
        "number verify evidence class A",
        "number verify source_doc stored",
        "number verify person recorded in notes",
        "number check verified table",
        "number check questionable table",
        "number check unknown table none",
        "number verify already verified idempotent",
        "number log on verified row bumps count",
        "number verify never-logged -> 404",
    ]
    # Probe: GET /number/check for a never-logged number. This detects
    # whether the tables exist WITHOUT touching the catalog — a log
    # probe with criteria would 400 on a deployment where the
    # proprietary catalog is not installed, masking the missing-tables
    # state. Tables exist -> 200 table "none"; missing -> 502.
    r = client.get("/number/check", params={"target": "+15550199"},
                   headers=auth_headers())
    if r.status_code == 502 and "number tables not created yet" in str(
            r.json().get("detail", "")):
        skip("number tables not created yet — run "
             "number-log-two-tables.sql in the Supabase SQL editor, "
             "then re-run", _number_db_checks)
    else:
        # First log: +15550101 (PH-06, class B -> credit -2.5).
        r = client.post("/number/log",
                        json={"target": "+15550101", "channel": "call",
                              "evidence_class": "B", "criteria_codes": ["PH-06"],
                              "pattern_tags": ["daily_repeat"],
                              "content_excerpt": "[TEST] synthetic sighting"},
                        headers=auth_headers())
        ok = r.status_code == 200
        body = r.json() if ok else {}
        check("number log 200", ok, f"got {r.status_code}")
        check("number log table questionable",
              body.get("table") == "questionable", f"table={body.get('table')}")
        check("number log standing observed",
              body.get("standing") == "observed", f"standing={body.get('standing')}")
        check("number log credit -2.5 (PH-06 w5 B)",
              body.get("credit") == -2.5, f"credit={body.get('credit')}")
        check("number log created", body.get("created") is True)
        check("number log contact_count 1", body.get("contact_count") == 1,
              f"got {body.get('contact_count')}")
        first_id = (body.get("row") or {}).get("id")
        # Repeat sighting: same row, counters bump, class never upgrades.
        r = client.post("/number/log",
                        json={"target": "+15550101", "channel": "call",
                              "evidence_class": "B",
                              "criteria_codes": ["PH-06", "PH-07"],
                              "pattern_tags": ["daily_repeat", "marketing"]},
                        headers=auth_headers())
        ok = r.status_code == 200
        body2 = r.json() if ok else {}
        check("number log repeat 200", ok, f"got {r.status_code}")
        check("number log repeat same id",
              bool(first_id) and (body2.get("row") or {}).get("id") == first_id,
              f"first_id={first_id!r} repeat_id={(body2.get('row') or {}).get('id')!r}")
        check("number log repeat contact_count 2",
              body2.get("contact_count") == 2,
              f"got {body2.get('contact_count')}")
        check("number log repeat evidence class stays B",
              (body2.get("row") or {}).get("evidence_class") == "B",
              f"class={(body2.get('row') or {}).get('evidence_class')}")
        check("number log repeat criteria merged",
              set((body2.get("row") or {}).get("criteria_codes") or [])
              == {"PH-06", "PH-07"},
              f"codes={(body2.get('row') or {}).get('criteria_codes')}")
        # Credit grows only by the NEW criterion PH-07 (w3 risk B):
        # -2.5 + (-1.5) = -4.0. The re-logged PH-06 adds nothing.
        check("number log repeat credit -4.0 (only new criterion added)",
              body2.get("credit") == -4.0, f"credit={body2.get('credit')}")
        # Credit variants, one insert each.
        r = client.post("/number/log",
                        json={"target": "+15550103", "evidence_class": "A",
                              "criteria_codes": ["PH-03"]},
                        headers=auth_headers())
        body = r.json() if r.status_code == 200 else {}
        check("number log confirmation credit +2.0 (PH-03 w2 A)",
              r.status_code == 200 and body.get("credit") == 2.0,
              f"got {r.status_code} credit={body.get('credit')}")
        r = client.post("/number/log",
                        json={"target": "+15550104", "evidence_class": "A",
                              "criteria_codes": ["PH-01"]},
                        headers=auth_headers())
        body = r.json() if r.status_code == 200 else {}
        check("number log neutral credit 0.0 (PH-01 w1 A)",
              r.status_code == 200 and body.get("credit") == 0.0,
              f"got {r.status_code} credit={body.get('credit')}")
        r = client.post("/number/log",
                        json={"target": "+15550105", "evidence_class": "B",
                              "criteria_codes": ["PH-06"],
                              "exchange_count": 20},
                        headers=auth_headers())
        body = r.json() if r.status_code == 200 else {}
        check("number log B over 12 exchanges credit -1.25",
              r.status_code == 200 and body.get("credit") == -1.25,
              f"got {r.status_code} credit={body.get('credit')}")
        r = client.post("/number/log",
                        json={"target": "+15550106", "evidence_class": "C",
                              "criteria_codes": ["PH-06"]},
                        headers=auth_headers())
        body = r.json() if r.status_code == 200 else {}
        check("number log C credit -1.25 (PH-06 w5 C)",
              r.status_code == 200 and body.get("credit") == -1.25,
              f"got {r.status_code} credit={body.get('credit')}")
        # Verify flow: log +15550102, refuse without a document,
        # promote with one, then check both tables.
        r = client.post("/number/log",
                        json={"target": "+15550102", "channel": "call",
                              "evidence_class": "C",
                              "criteria_codes": ["PH-10"],
                              "pattern_tags": ["marketing"]},
                        headers=auth_headers())
        check("number verify flow log 200", r.status_code == 200,
              f"got {r.status_code}")
        check("number verify without doc/person refused (already checked above)",
              True, "refusal covered by the 400 validation checks above")
        r = client.post("/number/verify",
                        json={"target": "+15550102",
                              "person_name": "Test Person",
                              "source_doc": "[TEST] synthetic source doc"},
                        headers=auth_headers())
        ok = r.status_code == 200
        body = r.json() if ok else {}
        check("number verify promotion 200", ok, f"got {r.status_code}")
        check("number verify promoted true", body.get("promoted") is True)
        check("number verify evidence class A",
              (body.get("row") or {}).get("evidence_class") == "A")
        check("number verify source_doc stored",
              (body.get("row") or {}).get("source_doc")
              == "[TEST] synthetic source doc")
        check("number verify person recorded in notes",
              "Test Person" in str((body.get("row") or {}).get("notes") or ""),
              f"notes={(body.get('row') or {}).get('notes')!r}")
        r = client.get("/number/check", params={"target": "+15550102"},
                       headers=auth_headers())
        body = r.json() if r.status_code == 200 else {}
        check("number check verified table",
              r.status_code == 200 and body.get("table") == "verified"
              and body.get("standing") == "verified",
              f"got {r.status_code} table={body.get('table')}")
        r = client.get("/number/check", params={"target": "+15550101"},
                       headers=auth_headers())
        body = r.json() if r.status_code == 200 else {}
        check("number check questionable table",
              r.status_code == 200 and body.get("table") == "questionable"
              and body.get("standing") == "observed",
              f"got {r.status_code} table={body.get('table')}")
        r = client.get("/number/check", params={"target": "+15550199"},
                       headers=auth_headers())
        body = r.json() if r.status_code == 200 else {}
        check("number check unknown table none",
              r.status_code == 200 and body.get("table") == "none"
              and body.get("standing") == "unknown"
              and body.get("credit") is None,
              f"got {r.status_code} table={body.get('table')}")
        # Idempotent re-verify, repeat log on a verified row, and
        # verify of a never-logged number.
        r = client.post("/number/verify",
                        json={"target": "+15550102",
                              "person_name": "Test Person",
                              "source_doc": "[TEST] synthetic source doc"},
                        headers=auth_headers())
        body = r.json() if r.status_code == 200 else {}
        check("number verify already verified idempotent",
              r.status_code == 200 and body.get("promoted") is False
              and body.get("already_verified") is True,
              f"got {r.status_code} promoted={body.get('promoted')}")
        r = client.post("/number/log",
                        json={"target": "+15550102", "channel": "call",
                              "evidence_class": "C"},
                        headers=auth_headers())
        body = r.json() if r.status_code == 200 else {}
        check("number log on verified row bumps count",
              r.status_code == 200 and body.get("table") == "verified"
              and body.get("contact_count") == 2,
              f"got {r.status_code} table={body.get('table')} "
              f"count={body.get('contact_count')}")
        r = client.post("/number/verify",
                        json={"target": "+15550199",
                              "person_name": "Test Person",
                              "source_doc": "[TEST] synthetic source doc"},
                        headers=auth_headers())
        check("number verify never-logged -> 404", r.status_code == 404,
              f"got {r.status_code}")

    # --- Cleanup: remove the synthetic verified_scams test row ---
    # (Uses the service directly is out of scope; the test row is
    # clearly marked [TEST] and uses a fictional 555 number.)
    print("\nNOTE: synthetic verified_scams row for +15559876543 is marked")
    print("[TEST] and uses a fictional number. Remove it in Supabase if")
    print("you want a clean table (DELETE FROM verified_scams WHERE")
    print("target = '+15559876543').")
    # Number-log test rows (fictional 555-01xx) in both tables.
    if _sb_url and _sb_key:
        try:
            _sb_client = httpx.Client(timeout=30, trust_env=False,
                                      proxy=_proxy)
            for _table in ("verified_numbers", "questionable_numbers"):
                _sb_client.delete(
                    f"{_sb_url}/rest/v1/{_table}",
                    params={"number_e164": "ilike.+155501%"},
                    headers={"apikey": _sb_key,
                             "Authorization": f"Bearer {_sb_key}"},
                )
            _sb_client.close()
        except Exception:
            pass

    passed = sum(1 for _, ok, _ in RESULTS if ok)
    total = len(RESULTS)
    print(f"\n{passed}/{total} checks passed.")
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
