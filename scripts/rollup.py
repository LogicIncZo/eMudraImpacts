#!/usr/bin/env python3
"""Roll impacted.csv up to one row per domain, attributing missing chain roots.

results/impacted-domains-summary.csv columns:
  domain, verdict, leaf_issuers, attributed_roots, impacted_hosts, expired_leaves
"""
import csv
from collections import defaultdict

ISSUER_ROOT = {
    "EM DV TLS CA - G2A-1": "emSign Root TLS CA - G1 (x-signed by emSign Root CA - G1)",
    "EM OV TLS CA - G2A-1": "emSign Root TLS CA - G1 (x-signed by emSign Root CA - G1)",
    "EM EV TLS CA - G2A-1": "emSign Root TLS CA - G1 (x-signed by emSign Root CA - G1)",
    "emSign SSL CA - G1": "emSign Root CA - G1",
    "eMudhra RSA Extended Validation Secure Server CA": "eMudhra legacy root (emSign family)",
}

by_dom = defaultdict(list)
for r in csv.DictReader(open("results/impacted.csv")):
    by_dom[r["domain"]].append(r)

rows_out = []
for dom, rs in sorted(by_dom.items()):
    issuers = sorted({r["leaf_issuer"] for r in rs})
    roots = set()
    for r in rs:
        if r["chain_roots"]:
            roots.update(x.strip() for x in r["chain_roots"].split(";") if x.strip())
        if not r["chain_roots"] or "AAA" in r["chain_roots"]:
            roots.update(ISSUER_ROOT.get(i, "") for i in issuers if i in ISSUER_ROOT)
    verdict = "CONFIRMED-COMPROMISED-INT" if any(r["impacted"] == "CONFIRMED-COMPROMISED-INT" for r in rs) \
        else "G1-FAMILY (watch-list)"
    rows_out.append({
        "domain": dom,
        "verdict": verdict,
        "leaf_issuers": "; ".join(issuers),
        "attributed_roots": "; ".join(sorted(x for x in roots if x)),
        "impacted_hosts": len(rs),
        "expired_leaves": sum(1 for r in rs if r["expired"] == "YES"),
    })

with open("results/impacted-domains-summary.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(rows_out[0].keys()))
    w.writeheader()
    w.writerows(rows_out)
print(f"results/impacted-domains-summary.csv: {len(rows_out)} domains")
