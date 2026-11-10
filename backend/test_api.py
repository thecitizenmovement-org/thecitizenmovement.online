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


def check(name, ok, detail=""):
    RESULTS.append((name, bool(ok), detail))
    mark = "PASS" if ok else "FAIL"
    print(f"[{mark}] {name}" + (f" — {detail}" if detail else ""))


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

    # --- Cleanup: remove the synthetic verified_scams test row ---
    # (Uses the service directly is out of scope; the test row is
    # clearly marked [TEST] and uses a fictional 555 number.)
    print("\nNOTE: synthetic verified_scams row for +15559876543 is marked")
    print("[TEST] and uses a fictional number. Remove it in Supabase if")
    print("you want a clean table (DELETE FROM verified_scams WHERE")
    print("target = '+15559876543').")

    passed = sum(1 for _, ok, _ in RESULTS if ok)
    total = len(RESULTS)
    print(f"\n{passed}/{total} checks passed.")
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
