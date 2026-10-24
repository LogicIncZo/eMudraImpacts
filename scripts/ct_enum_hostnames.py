#!/usr/bin/env python3
"""Enumerate every CT-logged hostname for the impacted domains via crt.sh.

Reads impacted domain names (one per line, or --domains file), queries crt.sh
JSON per domain (small queries are reliable, unlike the wildcard pull), and
writes all distinct DNS identities to the output file. Sleeps to respect the
~50 req / 5 min rate limit.
"""
import json, re, subprocess, sys, time

domains_file = sys.argv[1] if len(sys.argv) > 1 else "data/impacted-domains.txt"
out_file = sys.argv[2] if len(sys.argv) > 2 else "data/impacted-domain-hostnames.txt"
SLEEP = float(sys.argv[3]) if len(sys.argv) > 3 else 7.0

domains = [l.strip() for l in open(domains_file) if l.strip()]
dns_re = re.compile(r"^(\*\.)?[a-z0-9]([a-z0-9_-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9_-]*[a-z0-9])?)+$")
names = set()
fails = []
for i, d in enumerate(domains, 1):
    try:
        p = subprocess.run(
            ["curl", "-s", "--max-time", "90",
             f"https://crt.sh/?q=%25.{d}&output=json&exclude=expired"],
            capture_output=True, timeout=100)
        recs = json.loads(p.stdout.decode("utf-8", "replace")) if p.stdout.strip() else []
        for r in recs:
            for field in ("common_name", "name_value"):
                v = r.get(field) or ""
                for n in v.split("\n"):
                    n = n.strip().lower().lstrip("*.")
                    if n.endswith("." + d) and dns_re.match(n):
                        names.add(n)
                    elif n == d:
                        names.add(n)
    except Exception as e:
        fails.append((d, str(e)[:80]))
    if i % 10 == 0:
        print(f"{i}/{len(domains)} domains, {len(names)} hostnames, {len(fails)} fails", flush=True)
    time.sleep(SLEEP)

with open(out_file, "w") as f:
    f.write("\n".join(sorted(names)) + "\n")
print(f"wrote {out_file}: {len(names)} hostnames for {len(domains)} domains; {len(fails)} failed: {fails[:5]}")
