#!/usr/bin/env python3
"""
Phone Number Module — scoring, criteria catalog, and number-log helpers
(Scam Intel v3.0 Phase 1.4).

Two-table OSINT log (verified_numbers / questionable_numbers), seeded from
live inbound traffic. Source spec: Telebot's Phone Number Module build
spec, delivered by Josh 2026-11-10
(phone-number-module-build-spec-2026-11-10.md).

Everything in this module is PURE (no network, no Supabase): the scoring
rules live here so they can be unit-tested without a server, and the
criteria catalog is DATA (criteria_catalog.json next to this file), so a
new check is a data change, not a code deploy.

The criteria catalog is PROPRIETARY and is held out of the public repo
— criteria_catalog.json is not committed there. When the file is absent
(the public checkout), load_criteria_catalog() returns an empty list
and the /number/log endpoint refuses criteria codes until the catalog
is installed from the private criteria store. Logging without criteria
codes still works (credit 0). The multiplier and polarity rules below
are generic methodology; the catalog itself (codes, families, weights,
labels) lives in the data file only.

Scoring rules (from the spec)
-----------------------------
* Every criterion has a polarity and a weight:
    risk          moves the number toward questionable (signed -)
    confirmation  moves it toward verified (signed +)
    neutral       descriptive fact, no direction (signed 0)
* Evidence class multiplies every weight:
    A documented   one source states both facts          x 1.00
    B derived      two facts are consistent              x 0.50
    C no rebuttal  nothing contradicts, none confirms    x 0.25
  B is halved again (x 0.25) when the area has more than 12 exchanges,
  so a thin match cannot pass as a strong one.
* B NEVER becomes A by repetition. Ten consistent signals do not add up
  to a document. The evidence class upgrades only when a document
  appears — which is why log_sighting() (in app.py) never changes the
  stored evidence class of an existing row, and only verify_number()
  (also in app.py) sets class A, and only with a source document that
  names both the number and the person.
* credit (the number stored in the table) is the SIGNED total:
  confirmation contributions are positive, risk contributions are
  negative, neutral contributes 0. A credit above 0 leans verified, a
  credit below 0 leans questionable, 0 means no directional evidence.
  (Worked examples live in the local unit test,
  test_number_log_unit.py, which runs against the private catalog and
  is held out of the public repo with it.)

Reporting discipline: standing stays 'observed', not 'accused'. The
tables record numbers, not people. Naming a person without a document
is the one thing that turns a log into a liability.

PH-01..PH-05 facts (NANP validity, line type, carrier, rate center,
VoIP designation) come from the existing /scan/phone path — the direct
Numverify call and the phonenumbers parse — not from the log endpoint.
No new lookups were added for this module (FREE ONLY).
"""

import json
import os
import re

import phonenumbers

_CATALOG_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "criteria_catalog.json"
)
_catalog = None

# Evidence-class multipliers (spec). B is halved again when the area has
# more than this many exchanges.
EVIDENCE_MULTIPLIERS = {"A": 1.0, "B": 0.5, "C": 0.25}
EXCHANGE_COUNT_THRESHOLD = 12

# Pattern-tag vocabulary (spec). Six numbers tagged rotating_chain read
# as one campaign, not six calls.
VALID_PATTERN_TAGS = frozenset({
    "rotating_chain",
    "daily_repeat",
    "marketing",
    "robocall",
    "spoof_suspect",
    "institutional_impersonation",
})

VALID_CHANNELS = frozenset({"call", "sms", "both"})
VALID_EVIDENCE_CLASSES = frozenset({"A", "B", "C"})

# Polarity sign for the signed credit total.
_POLARITY_SIGN = {"confirmation": 1, "risk": -1, "neutral": 0}


def load_criteria_catalog():
    """Load criteria_catalog.json (cached). Returns the list of
    criterion dicts (code, family, polarity, weight,
    requires_original, label). An unreadable/missing catalog returns
    an empty list — the caller must treat that as "no criteria known"
    and refuse to score, never as "everything is clean"."""
    global _catalog
    if _catalog is None:
        try:
            with open(_CATALOG_PATH) as f:
                data = json.load(f)
            _catalog = list(data.get("criteria", []) or [])
        except Exception:
            _catalog = []
    return _catalog


def get_criterion(code):
    """Return the catalog entry for a code, or None when unknown."""
    for entry in load_criteria_catalog():
        if entry.get("code") == code:
            return entry
    return None


def known_criteria_codes():
    """Set of all catalog codes (for endpoint validation)."""
    return {entry.get("code") for entry in load_criteria_catalog()}


def evidence_multiplier(evidence_class, exchange_count=None):
    """Multiplier for one evidence class.

    A -> 1.00, B -> 0.50, C -> 0.25. B is halved again (0.25) when the
    area has more than 12 exchanges. Raises ValueError on an unknown
    class — callers validate the class before scoring."""
    cls = (evidence_class or "").strip().upper()
    if cls not in EVIDENCE_MULTIPLIERS:
        raise ValueError(f"unknown evidence class: {evidence_class!r}")
    mult = EVIDENCE_MULTIPLIERS[cls]
    if cls == "B" and exchange_count is not None:
        try:
            if int(exchange_count) > EXCHANGE_COUNT_THRESHOLD:
                mult *= 0.5
        except (TypeError, ValueError):
            pass
    return mult


def compute_credit(criteria_codes, evidence_class, exchange_count=None):
    """Score a set of tripped criteria.

    criteria_codes: iterable of catalog codes.
    evidence_class: 'A', 'B', or 'C' (the class of the evidence behind
      these criteria — one class for the whole sighting).
    exchange_count: optional number of exchanges in the number's area
      (only matters for class B).

    Returns a dict:
      credit:               signed total (confirmation +, risk -, neutral 0)
      risk_total:           magnitude of the risk contributions
      confirmation_total:   magnitude of the confirmation contributions
      neutral_total:        magnitude of the neutral contributions (recorded,
                            never directional)
      breakdown:            per-criterion {code, family, polarity, weight,
                            multiplier, contribution} where contribution is
                            the SIGNED weight x multiplier
      unknown_codes:        codes not in the catalog (scored as 0, listed
                            so the caller can see them)
    The function never upgrades the evidence class: B stays B no matter
    how many criteria are passed. Upgrading needs a document, which is
    verify_number()'s job, not this function's.
    """
    mult = evidence_multiplier(evidence_class, exchange_count)
    breakdown = []
    unknown_codes = []
    risk_total = 0.0
    confirmation_total = 0.0
    neutral_total = 0.0
    credit = 0.0
    for code in dict.fromkeys(criteria_codes or []):
        entry = get_criterion(code)
        if entry is None:
            unknown_codes.append(code)
            continue
        weight = float(entry.get("weight", 0))
        polarity = entry.get("polarity", "neutral")
        sign = _POLARITY_SIGN.get(polarity, 0)
        contribution = sign * weight * mult
        breakdown.append({
            "code": code,
            "family": entry.get("family"),
            "polarity": polarity,
            "weight": weight,
            "multiplier": mult,
            "contribution": contribution,
        })
        magnitude = weight * mult
        if polarity == "risk":
            risk_total += magnitude
        elif polarity == "confirmation":
            confirmation_total += magnitude
        else:
            neutral_total += magnitude
        credit += contribution
    return {
        "credit": credit,
        "risk_total": risk_total,
        "confirmation_total": confirmation_total,
        "neutral_total": neutral_total,
        "breakdown": breakdown,
        "unknown_codes": unknown_codes,
    }


def normalize_e164(raw):
    """Canonical E.164 for the log's unique key (number_e164).

    Parses with phonenumbers (default region US) and formats E.164;
    falls back to digit rules (+1 for 10-digit NANP, + for 11-digit
    starting with 1) when parsing fails. Never raises: the last resort
    is the raw string as given."""
    s = (raw or "").strip()
    if not s:
        return s
    try:
        parsed = phonenumbers.parse(s, "US")
        return phonenumbers.format_number(
            parsed, phonenumbers.PhoneNumberFormat.E164
        )
    except Exception:
        pass
    digits = re.sub(r"\D", "", s)
    if s.startswith("+") and 7 <= len(digits) <= 15:
        return "+" + digits
    if len(digits) == 11 and digits.startswith("1"):
        return "+" + digits
    if len(digits) == 10:
        return "+1" + digits
    if len(digits) == 7:
        # 7-digit NANP local number — assume the US country code.
        return "+1" + digits
    return s
