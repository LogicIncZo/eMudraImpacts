#!/usr/bin/env python3
"""Discover new .gov.in / .nic.in domains by crawling homepage, robots.txt and
sitemap.xml of every TLS-reachable host from the main scan.

For each host: GET / (redirects followed, 2 MB cap), /robots.txt (plus up to 2
Sitemap: targets), /sitemap.xml. Every *.gov.in / *.nic.in hostname in any body
is harvested; registrable domains (last 3 labels) not already in the universe
are new candidates.

Outputs:
  data/discovered-domains.txt   new registrable domains (delta)
  data/discovered-other.txt     non gov.in/nic.in hostnames seen
  results/discovery-log.csv     per-host log
"""
import concurrent.futures as cf
import csv, os, re, subprocess

TLS_OK = "results/scan-all.csv"
KNOWN = "data/gov-domains.txt"
OUT_NEW = "data/discovered-domains.txt"
OUT_OTHER = "data/discovered-other.txt"
LOG = "results/discovery-log.csv"
WORKERS = int(os.environ.get("CRAWL_WORKERS", "60"))

# lookbehind rejects matches carved out of url-encoded sequences (%2F etc.)
DOM_RE = re.compile(r"(?<![a-zA-Z0-9%._-])[a-zA-Z0-9](?:[a-zA-Z0-9._-]{0,120}[a-zA-Z0-9])?\.(?:gov|nic)\.in", re.I)
known = {l.strip().lower() for l in open(KNOWN) if l.strip()}
known_doms = {d for d in known}
known_last3 = {".".join(d.split(".")[-3:]) for d in known}

new_hosts, other_hosts = set(), set()


def fetch(url, size_cap="2000000"):
    try:
        p = subprocess.run(
            ["curl", "-skL", "--max-time", "12", "--max-filesize", size_cap, url],
            capture_output=True, timeout=15)
        body = p.stdout.decode("utf-8", "replace")
        return body if len(body) > 50 else ""
    except Exception:
        return ""


def extract(body):
    for m in DOM_RE.finditer(body):
        h = m.group(0).lower().lstrip("._-")
        if h.endswith(".gov.in") or h.endswith(".nic.in"):
            new_hosts.add(h)
        else:
            other_hosts.add(h)


def crawl(host):
    port = host.get("port") or "443"
    base = f"https://{host['host']}" + (f":{port}" if port != "443" else "")
    bodies = []
    home = fetch(base + "/")
    if home:
        bodies.append(home)
    robots = fetch(base + "/robots.txt", "200000")
    sitemap_urls = []
    if robots:
        bodies.append(robots)
        sitemap_urls = [l.split(":", 1)[1].strip() for l in robots.splitlines()
                        if l.lower().startswith("sitemap:")][:2]
    for sm in [base + "/sitemap.xml"] + sitemap_urls:
        b = fetch(sm)
        if b:
            bodies.append(b)
    found = 0
    for b in bodies:
        before = len(new_hosts)
        extract(b)
        found += len(new_hosts) - before
    return {"host": host["host"], "pages": len(bodies), "new_hostnames_found": found}


hosts = []
for r in csv.DictReader(open(TLS_OK)):
    if r["tls"] == "ok":
        hosts.append({"host": r["host"], "port": r["port"]})
print(f"crawling {len(hosts)} TLS-reachable hosts", flush=True)

log = []
with cf.ThreadPoolExecutor(WORKERS) as ex:
    futs = [ex.submit(crawl, h) for h in hosts]
    for i, fut in enumerate(cf.as_completed(futs), 1):
        try:
            log.append(fut.result())
        except Exception as e:
            log.append({"host": "?", "pages": 0, "new_hostnames_found": 0})
        if i % 500 == 0:
            print(f"  {i}/{len(hosts)} crawled, {len(new_hosts)} hostnames seen", flush=True)

with open(LOG, "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=["host", "pages", "new_hostnames_found"])
    w.writeheader()
    w.writerows(log)

# reduce hostnames -> registrable domains (last 3 labels for gov.in/nic.in)
last3 = {".".join(h.split(".")[-3:]) for h in new_hosts}
new_dom = sorted(d for d in last3 if d not in known_last3 and d not in known_doms)
with open(OUT_NEW, "w") as f:
    f.write("\n".join(new_dom) + "\n")
with open(OUT_OTHER, "w") as f:
    f.write("\n".join(sorted(h for h in other_hosts)) + "\n")
print(f"new gov domains: {len(new_dom)} | other-domains seen: {len(other_hosts)}")
