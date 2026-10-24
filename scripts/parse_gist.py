#!/usr/bin/env python3
"""Extract .gov.in and .nic.in registrable domains from the cyb3r-n3rd gist dump.

Gist format: '# <section> (count)' headers followed by ' - <domain>' entries.
Writes one domain per line to data/gov-domains.txt.
"""
import re

SRC = "data/gist-govin.txt"
OUT = "data/gov-domains.txt"
KEEP = {"gov.in", "nic.in"}

sections: dict[str, list[str]] = {}
cur = None
for line in open(SRC, encoding="utf-8"):
    line = line.strip()
    m = re.match(r"^#\s+(\S.*?)(?:\s*\((\d+)\))?$", line)
    if m:
        cur = m.group(1).strip()
        sections.setdefault(cur, [])
        continue
    m = re.match(r"^-\s+(\S+)$", line)
    if m and cur is not None:
        sections[cur].append(m.group(1).lower())

doms = set()
for sec in KEEP:
    for d in sections.get(sec, []):
        d = d.strip(".*")
        if re.match(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9-]+)*\.(gov|nic)\.in$", d):
            doms.add(d)

with open(OUT, "w") as f:
    f.write("\n".join(sorted(doms)) + "\n")
print(f"{OUT}: {len(doms)} domains (gov.in={len(sections.get('gov.in', []))}, nic.in={len(sections.get('nic.in', []))})")
