# Scam Intel API — Specification (v3.0 Phase 1.4)

Base URL (local dev): `http://127.0.0.1:8000`
Binds **127.0.0.1 only**. Never expose publicly. The hosted service runs on
a small VPS/container (see README.md).

## Auth

Every endpoint except `GET /health` requires a bearer token:

```
Authorization: Bearer <SCAMINTEL_API_TOKEN>
```

- Missing or wrong token → `401 {"detail": "Unauthorized"}`.
- Supabase JWT verification replaces this bearer token in Phase 2 — not now.
- The token is set via the `SCAMINTEL_API_TOKEN` environment variable. If
  unset, the service generates a random one per run and prints it once.

## Common behaviour

- All scan endpoints validate the target with the same strict regexes as
  the hardened v3.0 dev `server.py`. Invalid input → `400`.
- Every completed scan writes one row to the Supabase `scans` table
  (`tool`, `target`, `target_type`, `result_summary`, `result` JSONB,
  `status`, `created_at`). The write uses the service_role key, which
  bypasses RLS. If Supabase is not configured, the scan still runs but
  the response has `"stored": false` and `scan_id: null`.
- `user_id` on a scan row is `null` until Phase 2 (Supabase JWT auth)
  populates it.
- Responses are JSON. Errors never include stack traces or secrets.

## Endpoints

### GET /health

Public liveness check. No auth.

Response `200`:
```json
{
  "status": "ok",
  "service": "scam-intel-api",
  "version": "3.0.0-phase1.4",
  "supabase_configured": true
}
```

### POST /scan/phone

Phone check: `phonenumbers` parse (carrier/region/validity) + PhoneInfoga
v2 scan + known-scam lookup against `verified_scams`.

Request:
```json
{ "target": "+15551234567" }
```

Response `200`:
```json
{
  "scan_id": "<uuid>",
  "tool": "phoneinfoga",
  "target": "+15551234567",
  "target_type": "phone",
  "status": "complete",
  "result_summary": "valid number; carrier: ...; region: ...",
  "result": {
    "parsed": {
      "e164": "+15551234567",
      "country_code": 1,
      "national_number": "5551234567",
      "possible": true,
      "valid": false,
      "region": "California",
      "carrier": "",
      "number_type": "FIXED_LINE_OR_MOBILE"
    },
    "phoneinfoga": { "ran": true, "output": "..." },
    "numverify": { "enabled": true, "status": "ran", "checked_at": "..." },
    "known_scam": false,
    "verified_scam": null
  },
  "known_scam": false,
  "stored": true
}
```

Notes:
- PhoneInfoga v2's default scanners return Google-search URL lists unless
  API keys are configured. Live carrier/VOIP enrichment needs API keys
  (not configured). The `phonenumbers` parse is the reliable local signal.
- `valid: false` for 555-01xx numbers is expected — they are fictional.
- `result.numverify`: when `NUMVERIFY_ENABLED` is `true` AND
  `NUMVERIFY_API_KEY` is set (free apilayer key), the backend calls
  the Numverify API directly at
  https://api.apilayer.net/numverify/api/validate and returns real
  carrier and line type (mobile / landline / VoIP) plus `valid`,
  `country_code`, `country_name`, `location`, and the full API JSON
  under `details`. **Gated off by default (Phase 1.4):**
  `NUMVERIFY_ENABLED` defaults to off, so the call is skipped
  entirely (`{ "enabled": false, "status": "SKIP", ... }` — never an
  error) and no quota is burned; the free plan caps at 100
  requests/month and PhoneInfoga + the local parse already cover
  phone checks. The key stays set in Render; set
  `NUMVERIFY_ENABLED=true` in the Render dashboard to turn it back
  on. PhoneInfoga's built-in numverify scanner is NOT used — it calls
  a dead endpoint (api.apilayer.com/number_verification
  /validate, Cloudflare 504) and misreports the failure as "Invalid
  authentication credentials"; it is disabled with `-D numverify` and
  PhoneInfoga's other scanners still run. When the key is absent the
  entry is `{ "enabled": false, "status": "SKIP", ... }` — a skip,
  never a fake clean. An invalid key is `ERR`, never a fake valid.
  The key is never returned in the response.

Errors: `400` invalid phone number. `401` bad/missing token.

### POST /scan/email

Email check: format validation + domain MX/A via DNS-over-HTTPS +
user-scanner registration check (210+ sites) + known-scam lookup
(email, then its domain).

Request:
```json
{ "target": "someone@example.com" }
```

Response `200` — same shape as `/scan/phone`, with:
- `tool`: `"email_check"`, `target_type`: `"email"`.
- `result.domain_mx`: MX records for the domain (DoH).
- `result.domain_a`: A records for the domain (DoH).
- `result.domain_has_mail`: boolean.
- `result.user_scanner`: `{ "tool": "user-scanner", "status": "FOUND" |
  "NONE" | "SKIP" | "ERR", "checked_at": "<UTC ISO>", "registered": [
  { "site", "category", "url", "profile", "login" } ], "registered_count",
  "not_registered_count", "error_count", "skipped_count", "total_modules",
  "errors": [ { "site", "reason" } ] }`. `status` is FOUND when the
  email is registered on at least one site, NONE when at least one
  module returned a definitive "not registered" and none registered,
  ERR when no module gave a definitive answer (or the tool failed), and
  SKIP when user-scanner is not installed. A module that errors is
  recorded as an error, never as "not registered". user-scanner is
  NEVER run with `--hudson` (infostealer corpus — prohibited).
- `result.verified_scam_domain`: the domain's row in `verified_scams`, if any.

Notes:
- The user-scanner step takes ~80 s (220 modules). Timeout is 240 s
  (`USER_SCANNER_TIMEOUT`).
- user-scanner is used for email only. Its full username run (2,510+
  sites) takes >4 min and is too slow for a synchronous call, so
  Maigret covers username.

Errors: `400` invalid email address. `401` bad/missing token.

### POST /scan/domain

Domain check: DNS (DoH A/MX/TXT) + RDAP (registrar/status/creation) +
subfinder subdomain enumeration + crt.sh certificate-transparency
subdomains + known-scam lookup.

Request:
```json
{ "target": "example.com" }
```

Response `200` — same shape, with:
- `tool`: `"domain_check"`, `target_type`: `"domain"`.
- `result.dns_a`, `result.dns_mx`, `result.dns_txt`.
- `result.rdap`: `{ "registrar", "status", "creation_date",
  "expiration_date", "last_changed", "handle" }` (null when RDAP fails).
- `result.subfinder`: `{ "tool": "subfinder", "status": "FOUND" | "NONE" |
  "SKIP" | "ERR", "checked_at": "<UTC ISO>", "subdomains": [ ... ],
  "total_found", "truncated" }`. Subfinder runs keyless sources only;
  keyed sources are reported as skipped by subfinder, never as "no
  subdomains". Stored subdomains are capped at 500
  (`SUBFINDER_MAX_RESULTS`); `total_found` is the full count.
- `result.crtsh`: `{ "tool": "crtsh", "source": "https://crt.sh",
  "status": "FOUND" | "NONE" | "ERR", "checked_at": "<UTC ISO>",
  "subdomains": [ ... ], "total_found" }`. A direct certificate-
  transparency query (one HTTPS call), a second subdomain source
  alongside subfinder.
- `result.subdomains`: the merged union of subfinder + crt.sh
  subdomains (sorted, deduplicated). `result.subdomain_count` is its
  length.

Notes:
- DNS uses DNS-over-HTTPS (Google, then Cloudflare). The local system
  resolver in this VM returns synthetic proxy addresses, so DoH is used.
- Registrar data uses RDAP over HTTPS (rdap.org). Direct WHOIS (port 43)
  is blocked in this environment.
- theHarvester is NOT used (blocked — see README.md).

Errors: `400` invalid domain. `401` bad/missing token.

### POST /scan/username

Username check: Maigret against the top-N sites + known-scam lookup.

Request:
```json
{ "target": "someusername" }
```

Response `200` — same shape, with:
- `tool`: `"maigret"`, `target_type`: `"username"`.
- `result.found_accounts`: list of `{ "site", "url", "username" }`.
- `result.found_count`: number of accounts found.
- `result.maigret`: `{ "ran": true, "output": "..." }` (tail of CLI output).

Notes:
- Maigret runs against the top 50 sites by default (`MAIGRET_TOP_SITES`).
  A full 509-site run takes ~3–4 minutes and is too slow for a
  synchronous API call. Timeout is 180 s (`MAIGRET_TIMEOUT`).
- Many sites block automated checks; a low count does not prove the
  username is unused.

Errors: `400` invalid username. `401` bad/missing token.

### POST /address/verify

Address check: parse with usaddress (in-process) + Geocodio (primary)
+ US Census Geocoder (fallback / second opinion) + Nominatim (third
opinion only, on disagreement) + known-scam / known-good lookups.
Verified-good addresses upsert into `verified_valid`
(`target_type: "address"`). This complements Stripe AVS/Radar — it
does not replace it.

Request:
```json
{ "target": "1600 Amphitheatre Parkway, Mountain View, CA 94043" }
```

Response `200` — same shape as the other scans, with:
- `tool`: `"address_check"`, `target_type`: `"address"`.
- `verdict`: `"FOUND" | "NONE" | "SKIP" | "ERR"` (top level, and
  inside `result`).
- `source`: `"geocodio" | "census" | "nominatim" | null` — which
  service produced the verdict.
- `standardized_address`, `accuracy`, `accuracy_type` (top level,
  and inside `result`).
- `result.parsed`: `{ "tool": "usaddress", "status": "FOUND" |
  "NONE" | "SKIP" | "ERR", "checked_at": "<UTC ISO>", "components":
  { "AddressNumber", "StreetName", "PlaceName", "StateName",
  "ZipCode", ... }, "parseable": true }`. Parsing only — never a
  verdict by itself.
- `result.geocodio`: `{ "tool": "geocodio", "source":
  "https://api.geocod.io/v2.1/geocode", "status": "FOUND" | "NONE" |
  "SKIP" | "ERR", "checked_at": "<UTC ISO>", "standardized_address",
  "accuracy" (0–1), "accuracy_type", "match_type", "location" }`.
  Verdict mapping: `rooftop` (parcel centroid arrives as
  `match_type`) with score >= 0.8 → FOUND;
  `range_interpolation` → FOUND (weak); `street_center` / `place` /
  `county` / `state` centroid or no match → NONE. No key → SKIP
  (no network call, never a fake clean). Bad key / 403 / 429 /
  timeout → ERR.
- `result.census`: `{ "tool": "census", "status": "FOUND" | "NONE" |
  "ERR", "checked_at": "<UTC ISO>", "standardized_address",
  "coordinates", "tiger_line" }`. Free, no key. A match confirms
  the address falls on a real TIGER street range — existence/range
  only, NOT deliverability (recorded on the step as a note).
- `result.nominatim`: `{ "tool": "nominatim", "status": "FOUND" |
  "NONE" | "SKIP" | "ERR", "checked_at": "<UTC ISO>",
  "standardized_address", "accuracy" (importance) }`. Free, no key.
  Third opinion only: consulted when Geocodio and Census disagree,
  or when both are unavailable. Max 1 request/sec (enforced),
  results cached, address text only — never a customer name.
- `result.known_valid`: whether the address is already in
  `verified_valid`. `verified_valid_id` (top level) is the upserted
  row's id when the verdict is FOUND, else null.

Verdict rules:
- Geocodio FOUND → FOUND (source geocodio).
- Geocodio NONE → NONE (flag for review). A Census range match does
  NOT override Geocodio's deliverability answer; the disagreement
  is recorded and Nominatim is consulted as the third opinion.
- Geocodio SKIP/ERR → Census decides: FOUND (weak, source census) /
  NONE / ERR (then Nominatim as last resort).
- A real API answer is a real verdict even if negative; a failed
  call is ERR, never a fake valid; a missing key is SKIP at the step
  level (with the Census fallback live, the key alone never decides
  the final verdict).

Notes:
- The `scans` row is stored with `target_type: "other"` until the
  `scans` CHECK constraint is widened to include `"address"` (see
  `scans-add-address-type.sql`); the row is never lost, and the
  backfill is `UPDATE scans SET target_type='address' WHERE
  tool='address_check'`.
- Geocodio free tier is 2,500 lookups/day, no card. The key lives in
  `GEOCODIO_API_KEY` (Render dashboard); it is never logged or
  returned.

Errors: `400` invalid address. `401` bad/missing token.

### POST /scam/report

Member submits a verified scam. Upserts into `verified_scams` (backend
service role only). If the target already exists, `reporter_count` is
incremented and `last_seen` refreshed.

Request:
```json
{
  "target": "+15551234567",
  "target_type": "phone",
  "evidence": "Called claiming to be the IRS; asked for gift cards."
}
```

- `target_type` must be one of `phone`, `domain`, `email`, `other`.
- `target` is validated the same way as the matching scan endpoint
  (`other` only needs a non-empty string, max 253 chars).
- `evidence` max 4000 characters.

Response `200` (the upserted row):
```json
{
  "target": "+15551234567",
  "target_type": "phone",
  "evidence": "Called claiming to be the IRS; asked for gift cards.",
  "reporter_count": 1,
  "first_seen": "2026-11-10T...",
  "last_seen": "2026-11-10T...",
  "id": "<uuid>"
}
```

Errors: `400` invalid target/target_type/evidence. `401` bad/missing
token. `502` could not write to Supabase.

### GET /scam/check?target=...

Instant "known scam?" lookup against `verified_scams`. Exact match
(case-insensitive).

Request: `GET /scam/check?target=%2B15551234567`

Response `200`:
```json
{ "target": "+15551234567", "known_scam": true, "verified_scam": { ... } }
```
or, when not found:
```json
{ "target": "+15551234567", "known_scam": false, "verified_scam": null }
```

Errors: `401` bad/missing token. `422` missing/empty `target` query param.

### POST /number/log

Phone Number Module (Phase 1.4): log one sighting of an inbound
number. Writes into `questionable_numbers` unless the number is
already verified (then it only bumps that row's `contact_count` and
`last_seen`). A repeat sighting never duplicates the row, never
upgrades its evidence class, and only adds the NEW criteria's credit
— B never becomes A by repetition.

Request:
```json
{
  "target": "+15550101",
  "channel": "call",
  "number_raw": "(555) 0101",
  "caller_id_name": "Unknown",
  "pattern_tags": ["daily_repeat"],
  "content_excerpt": "Same pitch as yesterday.",
  "evidence_class": "B",
  "criteria_codes": ["PH-06", "PH-07"],
  "exchange_count": 20,
  "source_doc": "",
  "notes": ""
}
```

- `target` is a phone number (same validation as `/scan/phone`).
  It is stored canonically as `number_e164` (E.164).
- `channel` must be `call`, `sms`, or `both` (default `call`).
- `evidence_class` must be `A`, `B`, or `C` (default `C`).
- `criteria_codes` must be codes from `criteria_catalog.json`
  (36 criteria: PH-01..14, SCAM-01..05, SOL-01..05, ORIG-01..05,
  ID-01..07). Unknown codes → `400`.
- `pattern_tags` must be from `rotating_chain`, `daily_repeat`,
  `marketing`, `robocall`, `spoof_suspect`,
  `institutional_impersonation`. Unknown tags → `400`.
- `exchange_count` (optional int) feeds the class-B thin-match
  penalty: B is halved again when the area has more than 12 exchanges.
- `content_excerpt` max 1000 chars, `source_doc` max 1000 chars,
  `notes` max 4000 chars.
- PH-01..PH-05 facts come from `/scan/phone` (Numverify + phonenumbers),
  not from this endpoint — no new lookups are made here.

Response `200`:
```json
{
  "target": "+15550101",
  "number_e164": "+15550101",
  "table": "questionable",
  "standing": "observed",
  "row": { "...": "the upserted row (credit, criteria_codes, ...)" },
  "credit": -4.0,
  "credit_breakdown": {
    "credit": -4.0, "risk_total": 4.0, "confirmation_total": 0.0,
    "neutral_total": 0.0,
    "breakdown": [ { "code": "PH-06", "polarity": "risk", "weight": 5,
                     "multiplier": 0.5, "contribution": -2.5 }, "..." ],
    "unknown_codes": []
  },
  "created": true,
  "contact_count": 1
}
```

`credit` is the row's stored SIGNED total (confirmation +, risk −,
neutral 0); `credit_breakdown` is this sighting's scoring. `standing`
is `observed` for questionable rows, `verified` for verified rows —
never `accused`.

Errors: `400` invalid input. `401` bad/missing token. `502` could
not write to Supabase, or the number tables do not exist yet (run
`number-log-two-tables.sql` in the Supabase SQL editor).

### POST /number/verify

Promote questionable → verified. Refuses unless a source document
names BOTH the number and the person: `person_name` and `source_doc`
are both required. Repetition never promotes — the number must
already be logged in `questionable_numbers`. Idempotent: an
already-verified number returns its verified row.

Request:
```json
{
  "target": "+15550102",
  "person_name": "Cary Heyoka",
  "source_doc": "Filing XYZ, page 3 (names number and person)",
  "notes": ""
}
```

Response `200`:
```json
{
  "target": "+15550102",
  "number_e164": "+15550102",
  "table": "verified",
  "standing": "verified",
  "row": { "...": "the verified row (evidence_class A, source_doc, ...)" },
  "person_name": "Cary Heyoka",
  "source_doc": "Filing XYZ, page 3 (names number and person)",
  "promoted": true,
  "already_verified": false
}
```

The row MOVES tables (insert into `verified_numbers` with
`evidence_class` `A`, then delete from `questionable_numbers`); the
verified person is recorded in `notes`.

Errors: `400` invalid input, or missing `person_name`/`source_doc`
(the refusal). `401` bad/missing token. `404` number was never
logged — log a sighting first. `502` Supabase write failed, or the
number tables do not exist yet.

### GET /number/check?target=...

Which table holds a number. `table` is `verified`, `questionable`,
or `none`; `standing` is `verified`, `observed`, or `unknown`.

Request: `GET /number/check?target=%2B15550101`

Response `200`:
```json
{
  "target": "+15550101",
  "number_e164": "+15550101",
  "table": "questionable",
  "standing": "observed",
  "row": { "...": "the row, or null" },
  "credit": -4.0,
  "criteria_codes": ["PH-06", "PH-07"],
  "pattern_tags": ["daily_repeat", "marketing"]
}
```

Errors: `400` invalid phone number. `401` bad/missing token.
`422` missing/empty `target` query param. `502` the number tables
do not exist yet.

### Scoring (Phone Number Module)

- Criteria catalog: `backend/criteria_catalog.json` — 36 criteria
  with code, family, polarity, weight, `requires_original`, label.
  The catalog is DATA, not code: a new check is a data change.
  PROPRIETARY — held out of this public repo (not committed). When
  the file is absent, `/number/log` refuses criteria codes until it
  is installed from the private criteria store; logging without
  criteria codes still works.
- Evidence class multiplies every weight: A ×1.00, B ×0.50, C ×0.25.
  B is halved again (×0.25) when the area has more than 12 exchanges.
  B never becomes A by repetition.
- `credit` is the SIGNED total: confirmation +, risk −, neutral 0.
  Above 0 leans verified, below 0 leans questionable, 0 means no
  directional evidence.
- `requires_original` (ORIG-01..05, ID-05, ID-06) means the criterion
  can only be satisfied by the original item, never by a screenshot
  or copy.
- DDL: `number-log-two-tables.sql` (run in the Supabase SQL editor).
  RLS matches `verified_scams` / `verified_valid`: members read all
  rows; writes go through the backend (service role) only.

## Error reference

| Status | Meaning |
|--------|---------|
| 400 | Invalid input (bad target, bad target_type, evidence too long). |
| 401 | Missing or wrong bearer token. |
| 422 | Missing/invalid query parameter or request body. |
| 502 | Supabase write/read failed (only for `/scam/report` and the `/number/*` endpoints; for `/number/*` it also means the number tables do not exist yet — run `number-log-two-tables.sql`). |
| 503 | A scan tool is unavailable (returned inside a scan `result`, not as HTTP 503). |

## Rate / concurrency limits

- Max 3 concurrent scans (`MAX_CONCURRENT_SCANS`). Extra requests wait
  for a slot. There is no per-user quota yet — that arrives with Phase 3
  (Stripe + `usage_quotas`).
- Per-tool timeouts: PhoneInfoga 90 s, Maigret 180 s, user-scanner 240 s,
  subfinder 90 s, HTTP (DoH/RDAP/Supabase/crt.sh) 15 s. A tool timeout is
  recorded in the scan `result`, not hidden.

## What is NOT in Phase 1

- Supabase JWT auth (Phase 2 — replaces the bearer token).
- Quotas / Stripe gating (Phase 3).
- `users`, `usage_quotas`, `payments` tables (Phase 2/3).
- A public URL / hosted deployment (see README.md — VPS/container needed).
