#!/usr/bin/env python3
"""Dump the IGOD (india.gov.in) state web directory for every state/UT code
and extract .gov.in / .nic.in domains not already in the scan universe.

Recipe (from LogicIncZo/TNGOD build): POST to the web-directory resolver with
category=sg + state_id=<CODE>, querytype=WebdirectoryCategorydetalsList.

Outputs:
  data/igod-domains.txt        new gov.in/nic.in registrable domains (delta)
  data/igod-all-hostnames.txt  every gov.in/nic.in hostname seen (dedup)
  data/igod-other-domains.txt  non-gov.in/nic.in domains (ac.in, com, org, ...)
  results/igod-dump.csv        full entries (title, url, state, type)
"""
import csv, json, re, subprocess, time
from urllib.parse import urlparse

STATES = "AN AP AR AS BR CH CT DN DL GA GJ HR HP JK JH KA KL LA LD MP MH MN ML MZ NL OD PY PB RJ SK TN TS TR UP UT WB".split()

URL = "https://www.india.gov.in/directory/web-directory/api"
known = {l.strip().lower() for l in open("data/gov-domains.txt") if l.strip()}
known_last3 = {".".join(d.split(".")[-3:]) for d in known}


def post(state, pageno=1):
    body = {"dataval": {"clientvalue": "client",
                        "mustvalue": [{"fieldName": "category", "fieldValue": "sg"},
                                      {"fieldName": "state_id", "fieldValue": state}],
                        "pageno": pageno, "pageSize": 500, "shouldvalue": [],
                        "querytype": "WebdirectoryCategorydetalsList"}}
    p = subprocess.run(["curl", "-s", "--max-time", "90", "-X", "POST", URL,
                        "-H", "content-type: application/json",
                        "-H", "user-agent: Mozilla/5.0", "-d", json.dumps(body)],
                       capture_output=True, timeout=100)
    return json.loads(p.stdout.decode("utf-8", "replace"))


rows_out, all_hosts, other = [], set(), set()
for i, st in enumerate(STATES, 1):
    try:
        data = post(st)
        node = data["resultdata"]["data"]["getIgodWebDirectoryByFilters"]
        total, results = node.get("total", 0), list(node.get("results") or [])
        page = 1
        while len(results) < total and page < 12:
            page += 1
            time.sleep(1.5)
            node = post(st, page)["resultdata"]["data"]["getIgodWebDirectoryByFilters"]
            results.extend(node.get("results") or [])
        for r in results:
            for k in ("url", "url_1"):
                u = (r.get(k) or "").strip()
                if not u or u.lower() in ("http://na", "https://na", "na"):
                    continue
                host = urlparse(u if "://" in u else "http://" + u).hostname
                if not host:
                    continue
                host = host.lower().lstrip("*.").strip(".")
                if "." not in host or " " in host:
                    continue
                rows_out.append({"state": st, "title": r.get("title", ""),
                                 "type": r.get("organization_type", ""), "url": u,
                                 "host": host})
                if host.endswith(".gov.in") or host.endswith(".nic.in"):
                    all_hosts.add(host)
                else:
                    other.add(host)
        print(f"{i:2d}/{len(STATES)} {st}: total={total} rows={len(results)}", flush=True)
    except Exception as e:
        print(f"{i:2d}/{len(STATES)} {st}: FAILED {str(e)[:80]}", flush=True)
    time.sleep(1.5)

with open("results/igod-dump.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=["state", "title", "type", "url", "host"])
    w.writeheader()
    w.writerows(rows_out)

last3 = {".".join(h.split(".")[-3:]) for h in all_hosts}
new = sorted(d for d in last3 if d not in known_last3)
with open("data/igod-domains.txt", "w") as f:
    f.write("\n".join(new) + "\n")
with open("data/igod-all-hostnames.txt", "w") as f:
    f.write("\n".join(sorted(all_hosts)) + "\n")
with open("data/igod-other-domains.txt", "w") as f:
    f.write("\n".join(sorted(other)) + "\n")
print(f"entries={len(rows_out)} gov-hostnames={len(all_hosts)} new-domains={len(new)} other={len(other)}")
