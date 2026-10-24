# eMudhra CA Compromise — Incident Brief (for G1/G3 removal impact study)

## What happened
- Reporter disclosed a compromise affecting **eight eMudhra intermediate CA keys**.
- The intermediates are cross-signed by **two roots**:
  1. `emSign ECC Root CA - G3` (O=eMudhra Technologies Limited, C=IN) — **trusted in Chrome, Mozilla, Microsoft** stores.
  2. Sectigo's `AAA Certificate Services` (Comodo) cross-sign — sectigo revoked the cross-signatures 2026-10-19; Chrome/Mozilla now mark it Removed.
- A newer Microsoft-only root `emSign Root TLS CA - G3` (created 2024-02-08, EC P-384) is the **direct issuer** of the compromised intermediates (Microsoft store only).
- Incident page: https://emudhra.we-have-a-problem.com/ · Mozilla Bugzilla **2083449**.

## The eight compromised intermediates (IOCs — leaf issuer CNs)
| Common name | Operator | Issues |
|---|---|---|
| EM DV TLS CA - G3B | eMudhra BV (NL) | TLS |
| EM OV TLS CA - G3B | eMudhra BV (NL) | TLS |
| EM EV TLS CA - G3B | eMudhra BV (NL) | TLS |
| EM DV TLS CA - G3C | eMudhra Inc (US) | TLS |
| EM OV TLS CA - G3C | eMudhra Inc (US) | TLS |
| EM EV TLS CA - G3C | eMudhra Inc (US) | TLS |
| EM OV CS CA - G3B | eMudhra BV (NL) | Code signing |
| EM OV CS CA - G3C | eMudhra Inc (US) | Code signing |

Data source: `data/impacted-intermediates.json`, `data/roots.json` (mirrored from incident site).

## Root trust-store status (from roots.json)
| Root | Chrome | Mozilla | Microsoft |
|---|---|---|---|
| emSign ECC Root CA - G3 | Included (removal **2026-10-27**) | Included | Included |
| emSign Root TLS CA - G3 | Not included | Not included | Included |
| emSign Root CS CA - G3 | Not included | Not included | Included |
| AAA Certificate Services | Removed | Removed | Included |

## Blocking / removal timeline (UTC)
- **2026-10-17** — Chrome & Firefox blocked the compromised keys
- **2026-10-19** — Apple & Android blocked; **Sectigo revoked its cross-signatures**
- **2026-10-20** — Microsoft blocked the certificates
- **2026-10-27** — Chrome removes `emSign ECC Root CA - G3` from its root store

Note: because clients vary in CRL enforcement, a site can still "work" in one browser
while already dead in another (cross-sign revocation vs. hard root removal).

## Relevance to Indian government sites
eMudhra is a major CCA-licensed CA and sells TLS via its emSign brand; several Indian
gov / PSU sites use emSign-issued TLS. Any leaf issued by the six TLS intermediates
above (or older `emSign Root CA - G1` chains also being wound down) will fail in
Chrome/Firefox/Edge once the roots are pulled. This project inventories affected
`*.gov.in` / `*.nic.in` sites so owners can be alerted to reissue certificates.

## Remediation (one line)
Reissue TLS certs from a non-eMudhra CA (or CCA India chain), redeploy server-side;
update client trust stores (ca-certificates, certifi ≥ 2026.10.19, Go 1.27.3+/Node 22.23.4+,
rebuild containers older than 2026-10-20; Java/Bun still unfixed as of 2026-10-21).

## Sources
- https://emudhra.we-have-a-problem.com/ (researcher incident page + JSON IOCs)
- https://illumen.io/security-bulletins/emudhra-ca-compromise (timeline & client fixes)
- https://convika.com/blog/chrome-removes-emudhra-root-2026-10-27 (Chrome date)
- Mozilla Bugzilla 2083449
