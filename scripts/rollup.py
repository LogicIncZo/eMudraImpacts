#!/usr/bin/env python3
"""Roll impacted.csv up to per-domain summary and split the two impact lists.

Outputs:
  results/impacted-domains-summary.csv  one row per domain (site table source)
  results/g1-impact-list.csv            endpoint-level list, emSign G1 family
  results/g3-impact-list.csv            endpoint-level list, compromised G3
                                        intermediates (currently 0 rows)
"""
import csv
from collections import defaultdict

ROOTS = "results"


def g1_path(leaf_issuer: str) -> str:
    if "G2A-1" in leaf_issuer:
        return "emSign Root TLS CA - G1 (MS-only, x-signed by legacy G1)"
    if leaf_issuer == "emSign SSL CA - G1":
        return "emSign Root CA - G1 (legacy, direct)"
    if leaf_issuer.startswith("eMudhra"):
        return "eMudhra legacy root (emSign family)"
    return "other"


rows = list(csv.DictReader(open(f"{ROOTS}/impacted.csv")))
by_dom = defaultdict(list)
for r in rows:
    by_dom[r["domain"]].append(r)

# --- domain summary ----------------------------------------------------------
out_dom = []
for dom, rs in sorted(by_dom.items()):
    issuers = sorted({r["leaf_issuer"] for r in rs})
    roots = set()
    for r in rs:
        if r["chain_roots"]:
            roots.update(x.strip() for x in r["chain_roots"].split(";") if x.strip())
        if not r["chain_roots"] or "AAA" in r["chain_roots"]:
            roots.update("emSign Root CA - G1" for _ in [0]
                         if any("G2A-1" in i or i == "emSign SSL CA - G1" for i in issuers))
    verdict = ("CONFIRMED-COMPROMISED-INT"
               if any(r["impacted"] == "CONFIRMED-COMPROMISED-INT" for r in rs)
               else "G1-FAMILY (watch-list)")
    out_dom.append({
        "domain": dom,
        "verdict": verdict,
        "leaf_issuers": "; ".join(issuers),
        "attributed_roots": "; ".join(sorted(x for x in roots if x)),
        "impacted_hosts": len(rs),
        "expired_leaves": sum(1 for r in rs if r["expired"] == "YES"),
    })
with open(f"{ROOTS}/impacted-domains-summary.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(out_dom[0].keys()))
    w.writeheader()
    w.writerows(out_dom)

# --- G1 impact list (endpoint level) -----------------------------------------
g1_fields = ["host", "domain", "leaf_issuer", "g1_path", "presented_roots",
             "verify_code", "http_status", "expired"]
g1 = []
for r in sorted(rows, key=lambda x: (x["domain"], x["host"])):
    if r["impacted"] != "CONFIRMED-COMPROMISED-INT":
        g1.append({
            "host": r["host"], "domain": r["domain"], "leaf_issuer": r["leaf_issuer"],
            "g1_path": g1_path(r["leaf_issuer"]),
            "presented_roots": r["chain_roots"], "verify_code": r["verify_code"],
            "http_status": r["http_status"], "expired": r["expired"],
        })
with open(f"{ROOTS}/g1-impact-list.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=g1_fields)
    w.writeheader()
    w.writerows(g1)

# --- G3 impact list (endpoint level) -----------------------------------------
g3_fields = ["host", "domain", "leaf_issuer", "compromised_intermediate",
             "verify_code", "http_status", "expired"]
g3 = []
for r in sorted(rows, key=lambda x: (x["domain"], x["host"])):
    if r["impacted"] == "CONFIRMED-COMPROMISED-INT":
        g3.append({
            "host": r["host"], "domain": r["domain"], "leaf_issuer": r["leaf_issuer"],
            "compromised_intermediate": r["matched_intermediates"],
            "verify_code": r["verify_code"], "http_status": r["http_status"],
            "expired": r["expired"],
        })
with open(f"{ROOTS}/g3-impact-list.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=g3_fields)
    w.writeheader()
    w.writerows(g3)

n_direct = sum(1 for x in g1 if "legacy, direct" in x["g1_path"])
n_cross = sum(1 for x in g1 if "Root TLS CA" in x["g1_path"])
print(f"impacted-domains-summary.csv: {len(out_dom)} domains")
print(f"g1-impact-list.csv: {len(g1)} endpoints ({n_direct} legacy-direct, {n_cross} via Root TLS CA - G1)")
print(f"g3-impact-list.csv: {len(g3)} endpoints")
