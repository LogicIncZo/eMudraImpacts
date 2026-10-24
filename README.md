# eMudraImpacts

Inventory of Indian government websites whose TLS certificates will break after the
**eMudhra CA compromise / emSign G1–G3 root removal from browser & OS trust stores**.

> **Deadline: Chrome removes `emSign ECC Root CA - G3` on 2026-10-27.**
> Microsoft has blocked the compromised intermediates since 2026-10-20 (any client
> enforcing CRLs on the Sectigo AAA cross-sign is already failing).

Full incident background, exact intermediate/root IOCs and the vendor timeline:
[notes/incident-brief.md](notes/incident-brief.md).

## Scope
- **9,670 registrable domains**: 7,259 `*.gov.in` + 2,454 `*.nic.in`
  (source: [cyb3r-n3rd gist](https://gist.github.com/cyb3r-n3rd/f4e50f7c25eaa676bb99efba9c8619bf),
  deduplicated in `data/gov-domains.txt`).
- Per domain, `https://<domain>` and `https://www.<domain>` are probed on :443
  (fallback :8443); the presented chain is captured with `openssl s_client -showcerts`.

## Detection logic
| Verdict | Meaning |
|---|---|
| `CONFIRMED-COMPROMISED-INT` | leaf (or chain) issued by one of the 8 compromised intermediates (`EM DV/OV/EV TLS CA - G3B/G3C`, `EM OV CS CA - G3B/G3C`) — **must reissue** |
| `EMSIGN-FAMILY` | issued by another eMudhra/emSign intermediate (e.g. legacy `emSign Root CA - G1` chains) — in the G1/G3 removal blast radius, reissue recommended |

Non-eMudhra issuers (Sectigo, Let's Encrypt, NIC CCA chains, expired/self-signed…) are
recorded in `results/scan-all.csv` but are out of the emSign blast radius.

## Layout
```
data/          gov-domains.txt (seed list), gist dump, IOC JSONs from the incident site
scripts/       parse_gist.py, scan_tls.py (see headers for usage)
results/       impacted.csv  <- deliverable
               scan-all.csv, no-tls.csv, chains/<host>.pem (chain evidence)
notes/         incident-brief.md
```

## Usage
```bash
python3 scripts/parse_gist.py                          # rebuild seed list from gist
SCAN_WORKERS=80 python3 scripts/scan_tls.py data/gov-domains.txt   # full scan (~30 min)
```

## Findings (scan of 2026-10-24)

**495 HTTPS endpoints across 223 gov.in / nic.in domains present eMudhra/emSign TLS**
(lists: **G1 impact list** `results/g1-impact-list.csv` · **G3 impact list** `results/g3-impact-list.csv`
· per-domain summary `results/impacted-domains-summary.csv` · chain evidence in `results/chains/`).

- **G3 impact list: 0 endpoints.** No scanned gov site chains to the 8 compromised intermediates
  (`EM DV/OV/EV TLS CA - G3B/G3C`), so the 2026-10-27 Chrome removal hard-breaks none of them.
- **G1 impact list: all 495 endpoints**, split across two trust paths:
  - 135 endpoints — `emSign SSL CA - G1` → legacy `emSign Root CA - G1` (direct)
  - 358 endpoints — `EM * TLS CA - G2A-1` → `emSign Root TLS CA - G1` (Microsoft-only 2024 root) cross-signed by legacy G1
  All work today; they break if Chrome/Mozilla remove legacy `emSign Root CA - G1` (under evaluation),
  and eMudhra is exiting public TLS regardless — planned reissue recommended.
- Issuer breakdown of the 495: `EM DV TLS CA - G2A-1` (281), `emSign SSL CA - G1` (135),
  `EM OV TLS CA - G2A-1` (64), `EM EV TLS CA - G2A-1` (13), `eMudhra RSA EV` (2).
  30 of the 495 leaves are already expired.
- High-profile domains in the set: `indiapost.gov.in`, `karnataka.gov.in`, `kerala.gov.in`,
  `maharashtra.gov.in`, `up.nic.in`, `kar.nic.in`, `patnahighcourt.gov.in`, `jkhighcourt.nic.in`,
  `highcourtchd.gov.in`, `chandigarhpolice.gov.in`, `mahagst.gov.in`, `bangalorecustoms.gov.in`,
  `cpcb.nic.in`, `attendance.gov.in` (+ `sso.attendance.gov.in`), `lsgkerala.gov.in` (5 vhosts),
  `ncpcr.gov.in`, `peso.gov.in`, `cept.gov.in`.

Scan coverage: 9,670 domains → 17,166 apex/www candidates (6,024 served TLS, 11,142 no-TLS),
plus a 4,460-candidate common-vhost-prefix probe over the impacted domains (18 extra hits).

## Known limitations
- Only :443/:8443 HTTPS on apex + www is probed; additional vhosts of impacted domains
  can be enumerated from CT logs (crt.sh) once the impacted domain set is known.
- Shell/TLS on other ports (SMTP, RDP over 443-only appliances) is out of scope.
- The gist is the domain universe of record; domains registered after its snapshot
  date are not covered. `scripts/ct_enum_hostnames.py` enumerates every CT-logged
  hostname of the impacted domains via crt.sh for a later re-run (crt.sh was
  rate-limiting/502ing during this session's runs, so only apex+www + a common-vhost
  prefix probe were live-scanned).
