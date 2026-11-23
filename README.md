# Sentinel-BD

**An open threat intelligence platform focused on Bangladesh.** Sentinel-BD collects
indicators of compromise (malicious IPs, domains, URLs and file hashes) from public
feeds, scores how trustworthy each one is, flags those that concern Bangladesh, and
publishes blocklists that firewalls, DNS servers and SIEMs can use directly.

> **Status: Phase 1 (platform core) and the dashboard are complete.** Phishing-domain
> hunting (Phase 2) and the honeypot sensors (Phase 3) are next. See [Roadmap](#roadmap).

## Dashboard

One app serves the dashboard, the API and the feeds. Open `/` after starting it.

- **Lookup:** paste any IP, domain, URL or hash (defanged is fine) and get a verdict with a
  score ring. Press `/` from anywhere to jump to it.
- **Everything filters the explorer:** a day in the 30-day threat pulse, an impersonated
  brand (bKash, Nagad, banks), a malware family, a severity, a source. Filters live in the
  URL, so a view can be shared.
- **"Why this score?":** every indicator opens a panel that shows how its score was worked
  out (each source's weight, freshness decay, Bangladesh boost) and where it was seen.
- **Blocklist builder:** choose a type, drag the score threshold, see how many entries a
  feed would hold, and copy ready-made steps for pfSense, FortiGate, Palo Alto, MikroTik,
  BIND, Pi-hole or a STIX-capable SIEM.
- **Keyboard:** `j` / `k` move through threats, `Enter` opens one, `Esc` closes.
- **Safe by construction:** malicious values are shown defanged, inserted only as text,
  and never become links; the page runs under a strict Content-Security-Policy with no
  third-party scripts.

---

## What problem it solves

| Problem | What Sentinel-BD does |
|---|---|
| Global feeds list millions of indicators, with no way to tell what matters to Bangladesh | Tags every indicator for Bangladesh relevance: `.bd` domains, impersonation of bKash, Nagad, banks and telcos, and Bangladeshi IP space |
| Raw feeds are noisy and indicators go stale | Scores each indicator 0–100 from source reliability, agreement between sources, and age |
| Blocking the wrong thing breaks networks | Rejects private and reserved IPs, and allowlists platforms such as GitHub, Google and gov.bd from domain/IP blocking |
| Commercial threat intel costs too much for most Bangladeshi organisations | Free feeds in the formats firewalls already read |

## How it works

```
 Feodo Tracker ─┐
 URLhaus ───────┤                   ┌─ normalise + refang  (hxxp://evil[.]com → http://evil.com)
 ThreatFox ─────┼─► collectors ─────┼─ validate            (drop private IPs, junk values)
 OpenPhish ─────┘   (every 6 h)     ├─ deduplicate         (one row per indicator, one sighting per feed)
                                    ├─ Bangladesh tagging  (.bd, brand impersonation, BD IP space)
                                    └─ scoring             (reliability × agreement × decay + BD boost)
                                                   │
                                                   ▼
                                     PostgreSQL ─► FastAPI ─► /feeds/ip.txt     firewalls
                                                             /feeds/rpz.zone   DNS firewall
                                                             /feeds/stix.json  MISP, OpenCTI, SIEM
                                                             /api/v1/*         search, lookup, stats
```

### Scoring

```
p     = 1 − Π (1 − reliabilityᵢ × confidenceᵢ)    # agreement between sources (noisy-OR)
p    *= 0.5 ^ (age_days / half_life)              # IP 14 d, URL 30 d, domain 45 d, hashes never
score = 100·p (+10 if relevant to Bangladesh), capped at 100
```

One URLhaus report scores **85**. If OpenPhish also reports it, the score rises to **96**. A
botnet IP last seen two weeks ago drops to about **45**, which takes it out of the default
blocklist (score ≥ 50). Severity bands: high ≥ 80, medium ≥ 50, low below that.

### Bangladesh relevance

| Reason | Example |
|---|---|
| `tld:.bd` | `login.example.com.bd` |
| `impersonates:<brand>` | `bkash-reward-bd.top`, `dutchbangla-ibanking-login.xyz` (the real sites are never flagged) |
| `ip:bd-space` | an IP in address space APNIC allocated to Bangladesh |
| `geo:BD` | the source feed itself places it in Bangladesh |

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env                  # SQLite by default

python -m sentinel.bd update          # download Bangladeshi IP ranges from APNIC
python -m sentinel.ingest             # collect all feeds
uvicorn sentinel.api.main:app --reload
```

Open http://localhost:8000/docs for the interactive API.

Offline (no internet), using the sample data:

```bash
python -m sentinel.ingest --from-file urlhaus=tests/fixtures/urlhaus.csv \
                          --from-file feodotracker=tests/fixtures/feodo.json
```

Tests (SQLite, or PostgreSQL with `TEST_DATABASE_URL=postgresql://...`):

```bash
python -m pytest -q
```

## API

| Endpoint | Purpose |
|---|---|
| `GET /api/v1/indicators?type=&min_score=&bd_only=&source=&q=` | Search and filter |
| `GET /api/v1/lookup?value=hxxp://evil[.]com` | "Is this IP, domain, URL or hash known to be malicious?" (defanged input accepted) |
| `GET /api/v1/stats` | Counts by type, severity, source and malware family |
| `GET /api/v1/feed-runs` | Health of each collector run |
| `GET /feeds/{ip,domain,url,hash}.txt?min_score=50&bd_only=false` | Plain blocklists |
| `GET /feeds/rpz.zone` | DNS firewall zone |
| `GET /feeds/mikrotik.rsc` | RouterOS address-list script |
| `GET /api/v1/explain?type=&value=` | Step-by-step score breakdown |
| `GET /api/v1/feed-preview?kind=&min_score=&bd_only=` | Size of a feed before subscribing |
| `GET /feeds/stix.json` | STIX 2.1 bundle |

The API is **read-only**. Data enters only through the ingest job, so the public
service has no write endpoints to attack.

## Plugging it into a firewall

| Device | Where | Feed URL |
|---|---|---|
| **pfSense / OPNsense** | pfBlockerNG → IP → IPv4 → add list | `https://<host>/feeds/ip.txt` |
| **FortiGate** | Security Fabric → External Connectors → Threat Feeds → IP Address / Domain Name | `/feeds/ip.txt`, `/feeds/domain.txt` |
| **Palo Alto** | Objects → External Dynamic Lists (IP / Domain / URL) | `/feeds/ip.txt`, `/feeds/domain.txt`, `/feeds/url.txt?strip_scheme=true` |
| **MikroTik** | `/tool fetch` + `/import` on a schedule | `/feeds/mikrotik.rsc` |
| **BIND / Unbound** | Response Policy Zone | `/feeds/rpz.zone` |
| **Pi-hole** | Adlists | `/feeds/domain.txt` |
| **MISP / OpenCTI / Splunk** | STIX import | `/feeds/stix.json` |

Add `?bd_only=true` for threats aimed at Bangladesh only, or raise `min_score` to block less.

## Deploying (free tier)

1. **Database:** create a free PostgreSQL database on [Neon](https://neon.tech).
2. **Collection:** add repository secrets `DATABASE_URL` and `ABUSECH_AUTH_KEY` (free at
   [auth.abuse.ch](https://auth.abuse.ch)). The workflow `.github/workflows/ingest.yml`
   then runs every 6 hours.
3. **Dashboard + API:** on [Render](https://render.com) choose **New → Blueprint**, pick this
   repository (it reads `render.yaml`), and paste the same `DATABASE_URL` when asked.
   Any other Python host works too:
   `uvicorn sentinel.api.main:app --host 0.0.0.0 --port $PORT`.

## Project layout

```
sentinel/
  collectors/     one module per feed: fetch + parse
  indicators.py   types, refanging, normalisation, validation
  allowlist.py    never-block lists for the domain/IP feeds
  bd.py           Bangladesh relevance and APNIC IP ranges
  scoring.py      confidence model
  ingest.py       pipeline + CLI
  exporters.py    plain text, RPZ, STIX 2.1
  api/            FastAPI app (dashboard, API, feeds)
  web/            dashboard: index.html + assets/app.js, app.css (no build step)
tests/            tests with sample data from each feed
```

## Roadmap

- [x] **Phase 1, platform core:** 4 feeds, normalisation, scoring, Bangladesh tagging, API, firewall/RPZ/STIX feeds
- [ ] **Phase 2, phishing hunter:** live CertStream monitoring for bKash, Nagad and bank lookalike domains, with screenshots and visual similarity checks
- [ ] **Phase 3, honeynet:** Cowrie and Dionaea sensors producing first-hand attack data
- [ ] **Phase 4, correlation:** link phishing domains, honeypot attackers and feed indicators through shared infrastructure; TAXII 2.1 server
- [x] **Dashboard:** lookup, threat pulse, impersonated brands, explorer, score breakdown, blocklist builder
- [ ] More feeds: AlienVault OTX, CISA KEV, MalwareBazaar, PhishTank

## Ethics

Sentinel-BD only collects published threat data and, from Phase 3, data from attackers
who connect to its own sensors. It never scans or probes other people's systems, and it
never stores leaked personal data. Report false positives as GitHub issues.
