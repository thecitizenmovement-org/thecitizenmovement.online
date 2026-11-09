# Citizen OSINT Toolkit v1.0
### Shasta + Tehama · phone · identity · records · footprint

**Open it:** double-tap `index.html` on the phone, or open the hosted URL. Add to home screen for a one-tap launch.

**No keys. No accounts. No server.** Every analysis runs in the browser. Lookups you fire go straight from your device to the public registry, not through anything of mine.

## Tabs

**Phone** — parses any format, gives E.164, area code and region (all 58 CA prefixes included), flags synthetic patterns, scores burner likelihood structurally, and wires eight reverse-lookup routes. The chain tracer records every number that reaches you with role, note and timestamp, then draws a role map so you can see the ring behind the spam. Exports CSV.

**Identity** — email analysis with live MX check via Cloudflare DNS and a disposable-provider list. Name search builds seven dorks plus twelve source links, official courts first and brokers clearly second. Domain/IP runs live RDAP, plus Wayback history. Photo metadata reads EXIF including GPS coordinates and hands you a map link.

**Records** — 18 verified county, state and federal portals. CPRA and FOIA letter generator with statutory citations, response deadlines and segregation language. Officials/money section for Form 700 and campaign finance.

**Footprint** — 39 trackers covering people-search, background-check, marketing-data, property, jail rosters and court indexes. Three-way status per site (listed, opted out, confirmed removed) with progress counters and CSV/JSON export. CCPA deletion demand generator per broker.

**Breach** — eight breach and leak sources, prefilled from the email you enter.

**Case Log** — timestamped entries with type, target, finding and source URL. Exports CSV and Markdown, ready to append to the source index.

**About** — what it does not do, and four evidence-hygiene rules, plus a SHA-256 hasher for any file you pick.

## What it will not do, stated plainly
- It cannot identify a caller. No free service can. It gives you structure, a structural score, and the fastest route to each source.
- It cannot detect radio-layer interception. It gives you the paper trail to prove a port-out or SIM swap.
- It will not scrape sites that forbid it or log into anything. Evidence gathered against a site's terms is evidence opposing counsel attacks.

## Storage
Everything lives in this browser's localStorage under the `cosint_` prefix. Clear site data and it's gone. Export before you clear.

## Version
1.0 · built Nov 8, 2026 · tested: phone parser (7/7 assertions), JS syntax clean, zero external dependencies.
