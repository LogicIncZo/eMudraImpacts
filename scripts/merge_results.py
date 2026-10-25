#!/usr/bin/env python3
"""Compose root-level deliverables from per-scan subdirectories.

Scans always write into results/<name>/; this script composes:
  results/scan-all.csv   universe-coverage rows (main + expand scans)
  results/impacted.csv   union of every impacted.csv (main, expand, vhost probes, rebuild)
Run after any scan; idempotent (dedupe by host, main-scan rows win).
"""
import csv, os, re, subprocess

FIELDS = ["host", "domain", "port", "tls", "leaf_cn", "leaf_issuer", "leaf_org",
          "notBefore", "notAfter", "impacted", "matched_intermediates", "chain_roots",
          "chain_issuers", "verify_code", "http_status", "expired"]


def read_rows(path):
    if not os.path.exists(path):
        return []
    return list(csv.DictReader(open(path)))


# --- scan-all: universe coverage = main + expand ------------------------------
scan = []
for sub in ("main", "expand"):
    scan.extend(read_rows(f"results/{sub}/scan-all.csv"))
seen = set()
dedup = []
for r in scan:
    if r["host"] not in seen:
        seen.add(r["host"])
        dedup.append(r)
with open("results/scan-all.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=FIELDS, extrasaction="ignore")
    w.writeheader()
    w.writerows(dedup)
print(f"results/scan-all.csv: {len(dedup)} rows (main+expand)")

# --- impacted: union of every impacted.csv, later files win -------------------
imp, order = {}, []
for sub in ("main", "expand", "vhost-probe", "vhost-probe2", "rebuild"):
    for r in read_rows(f"results/{sub}/impacted.csv"):
        if r["host"] in imp:
            order.remove(r["host"]) if r["host"] in order else None
        imp[r["host"]] = r
        if r["host"] not in order:
            order.append(r["host"])
# hosts with prior chain evidence that a later re-scan timed out on stay in the
# list (NIC throttling makes timeouts non-proof); their live row data is used
known_hosts = {l.strip() for l in open("data/impacted-hosts-known.txt") if l.strip()}
rebuild_all = {r["host"]: r for r in read_rows("results/rebuild/scan-all.csv")}
for h in known_hosts - set(imp):
    r = rebuild_all.get(h)
    if r:
        r["impacted"] = "EMSIGN-FAMILY"
        pem = f"results/chains/{h}.pem"
        if os.path.exists(pem) and not r["leaf_issuer"]:
            try:
                p = subprocess.run(["openssl", "x509", "-in", pem, "-noout", "-subject", "-issuer"],
                                   capture_output=True, timeout=8)
                for line in p.stdout.decode("utf-8", "replace").splitlines():
                    k, _, v = line.partition("=")
                    if k.strip() == "subject":
                        m = re.search(r"CN\s*=\s*([^,/]+)", v)
                        r["leaf_cn"] = m.group(1).strip() if m else v.strip()
                    elif k.strip() == "issuer":
                        m = re.search(r"CN\s*=\s*([^,/]+)", v)
                        r["leaf_issuer"] = m.group(1).strip() if m else v.strip()
            except Exception:
                pass
        imp[h] = r
        order.append(h)

rows = [imp[h] for h in order]
rows.sort(key=lambda r: ({"CONFIRMED-COMPROMISED-INT": 0, "EMSIGN-FAMILY": 1}.get(r["impacted"], 2), r["domain"], r["host"]))
with open("results/impacted.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=FIELDS, extrasaction="ignore")
    w.writeheader()
    w.writerows(rows)
print(f"results/impacted.csv: {len(rows)} rows")
