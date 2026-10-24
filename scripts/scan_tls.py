#!/usr/bin/env python3
"""eMudraImpacts TLS chain scanner.

For every domain in the seed list, probes https://<domain> (then :8443, then www.<domain>)
and captures the presented certificate chain with openssl s_client -showcerts.

A host is flagged IMPACTED when the leaf issuer (or any chain element) matches the
compromised eMudhra intermediates (EM DV/OV/EV TLS CA - G3B/G3C) or carries eMudhra/
emSign branding (covers older emSign Root CA - G1 chains as well).

Outputs:
  results/scan-all.csv   every host where TLS was observed
  results/impacted.csv   only impacted hosts (the deliverable)
  results/no-tls.csv     hosts with no usable TLS on probed ports
  results/chains/<host>.pem  full presented chain for impacted hosts (evidence)
"""
import concurrent.futures as cf
import csv, os, re, subprocess, sys, time

SEED = sys.argv[1] if len(sys.argv) > 1 else "data/gov-domains.txt"
OUT = os.environ.get("SCAN_OUT", "results")
CHAINS = os.path.join(OUT, "chains")
WORKERS = int(os.environ.get("SCAN_WORKERS", "80"))
os.makedirs(CHAINS, exist_ok=True)

COMPROMISED_TLS = {
    "EM DV TLS CA - G3B", "EM OV TLS CA - G3B", "EM EV TLS CA - G3B",
    "EM DV TLS CA - G3C", "EM OV TLS CA - G3C", "EM EV TLS CA - G3C",
}
COMPROMISED_ALL = COMPROMISED_TLS | {"EM OV CS CA - G3B", "EM OV CS CA - G3C"}
# Catch-all for the eMudhra/emSign family: compromised G3 intermediates, plus
# legacy chains (emSign SSL CA - G1, emSign ECC SSL CA - G3, eMudhra CA ...).
FAMILY_RE = re.compile(r"em\s?sign|emudhra|em\s+(dv|ov|ev)\s+tls|em\s+ov\s+cs", re.I)
ROOT_NOTES = {
    "emSign ECC Root CA - G3": "trusted in Chrome+Mozilla+MS; Chrome removes 2026-10-27",
    "emSign Root TLS CA - G3": "Microsoft-only; direct issuer of compromised intermediates",
    "emSign Root CS CA - G3": "code-signing root (Microsoft)",
    "AAA Certificate Services": "Sectigo cross-sign root; cross-signs revoked 2026-10-19",
    "emSign Root CA - G1": "legacy G1 root, still trusted 2026-10-24; Chrome evaluating removal",
    "emSign Root CA - G2": "eMudhra G2 root",
    "emSign ECC Root CA - G4": "eMudhra G4 root",
}

DNS_RE = re.compile(r"^[a-z0-9]([a-z0-9_-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9_-]*[a-z0-9])?)+$")


def openssl_x509(pem: str) -> dict:
    p = subprocess.run(
        ["openssl", "x509", "-noout", "-subject", "-issuer", "-dates", "-serial"],
        input=pem.encode(), capture_output=True, timeout=8)
    info = {"subject": "", "issuer": "", "notBefore": "", "notAfter": "", "serial": ""}
    txt = p.stdout.decode("utf-8", "replace")
    for line in txt.splitlines():
        k, _, v = line.partition("=")
        k = k.strip()
        if k in info:
            info[k] = v.strip()
    return info


def cn_of(dn: str) -> str:
    m = re.search(r"CN\s*=\s*([^,/]+)", dn)
    return m.group(1).strip() if m else dn


def get_chain(host: str, port: int):
    """Return (pems, verify_code, error)."""
    cmd = ["openssl", "s_client", "-connect", f"{host}:{port}", "-servername", host,
           "-showcerts"]
    try:
        p = subprocess.run(cmd, input=b"", capture_output=True, timeout=14)
    except subprocess.TimeoutExpired:
        return None, "", "timeout"
    out = p.stdout.decode("utf-8", "replace")
    pems = re.findall(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", out, re.S)
    if not pems:
        return None, "", (p.stderr.decode("utf-8", "replace").strip()[:120] or "no-cert")
    m = re.search(r"Verify return code: (\d+ \([^)]*\))", out)
    return pems, (m.group(1) if m else "?"), None


def http_status(host: str, port: int) -> str:
    try:
        p = subprocess.run(
            ["curl", "-skI", "--max-time", "8", "-o", "/dev/null",
             "-w", "%{http_code}", f"https://{host}:{port}/" if port != 443 else f"https://{host}/"],
            capture_output=True, timeout=10)
        return p.stdout.decode().strip() or "err"
    except Exception:
        return "err"


def scan_host(host: str):
    domain = ".".join(host.split(".")[-3:]) if re.search(r"\.(gov|nic)\.in$", host) else host
    row = {"host": host, "domain": domain, "port": "", "tls": "", "leaf_cn": "",
           "leaf_issuer": "", "leaf_org": "", "notBefore": "", "notAfter": "",
           "impacted": "", "matched_intermediates": "", "chain_roots": "",
           "chain_issuers": "", "verify_code": "", "http_status": "", "expired": ""}
    got = None
    for port in (443, 8443):
        pems, vcode, err = get_chain(host, port)
        if pems:
            got = (port, pems, vcode)
            break
    if not got:
        row["tls"] = f"no-tls ({err})"
        return row
    port, pems, vcode = got
    row.update(port=str(port), tls="ok", verify_code=vcode)
    row["http_status"] = http_status(host, port)

    certs = [openssl_x509(p) for p in pems]
    leaf = certs[0]
    row["leaf_cn"] = cn_of(leaf["subject"])
    row["leaf_issuer"] = cn_of(leaf["issuer"])
    m = re.search(r"O\s*=\s*([^,/]+)", leaf["subject"])
    row["leaf_org"] = m.group(1).strip() if m else ""
    row["notBefore"], row["notAfter"] = leaf["notBefore"], leaf["notAfter"]
    if row["notAfter"]:
        try:
            t = time.strptime(row["notAfter"], "%b %d %H:%M:%S %Y %Z")
            row["expired"] = "YES" if time.mktime(t) < time.time() else "no"
        except ValueError:
            row["expired"] = "?"

    issuers = [cn_of(c["issuer"]) for c in certs]
    subjects = [cn_of(c["subject"]) for c in certs]
    row["chain_issuers"] = "; ".join(dict.fromkeys(issuers))

    matched = sorted({s for s in subjects if s in COMPROMISED_ALL} |
                     {i for i in issuers if i in COMPROMISED_ALL})
    family = sorted({n for n in issuers + subjects if FAMILY_RE.search(n)})
    row["matched_intermediates"] = "; ".join(matched or family)

    roots = [s for s, c in zip(subjects, certs) if s == cn_of(c["issuer"])]
    row["chain_roots"] = "; ".join(sorted(roots))

    if matched:
        row["impacted"] = "CONFIRMED-COMPROMISED-INT"
    elif family:
        row["impacted"] = "EMSIGN-FAMILY"
    else:
        row["impacted"] = "no"

    if row["impacted"] != "no":
        safe = re.sub(r"[^a-z0-9.-]", "_", host.lower())
        with open(os.path.join(CHAINS, safe + ".pem"), "w") as f:
            f.write("\n".join(pems) + "\n")
    return row


def candidates(domain: str):
    out = [domain]
    if not domain.startswith("www.") and os.environ.get("SCAN_NO_WWW") != "1":
        out.append("www." + domain)
    seen, res = set(), []
    for h in out:
        if DNS_RE.match(h) and h not in seen:
            seen.add(h)
            res.append(h)
    return res


def main():
    domains = [l.strip() for l in open(SEED) if l.strip()]
    hosts = [h for d in domains for h in candidates(d)]
    print(f"scanning {len(domains)} domains -> {len(hosts)} host candidates", flush=True)

    rows, done = [], 0
    with cf.ThreadPoolExecutor(WORKERS) as ex:
        futs = {ex.submit(scan_host, h): h for h in hosts}
        for fut in cf.as_completed(futs):
            try:
                rows.append(fut.result())
            except Exception as e:
                rows.append({"host": futs[fut], "domain": "", "port": "", "tls": f"error: {e}",
                             "leaf_cn": "", "leaf_issuer": "", "leaf_org": "", "notBefore": "",
                             "notAfter": "", "impacted": "", "matched_intermediates": "",
                             "chain_roots": "", "chain_issuers": "", "verify_code": "",
                             "http_status": "", "expired": ""})
            done += 1
            if done % 500 == 0:
                hits = sum(1 for r in rows if r["impacted"] not in ("no", ""))
                print(f"  {done}/{len(hosts)} scanned, {hits} impacted so far", flush=True)

    fields = list(rows[0].keys())
    rank = {"CONFIRMED-COMPROMISED-INT": 0, "EMSIGN-FAMILY": 1, "no": 2}
    rows.sort(key=lambda r: (rank.get(r["impacted"], 3), r["domain"], r["host"]))
    for name, subset in (("scan-all.csv", rows),
                         ("impacted.csv", [r for r in rows if r["impacted"] not in ("no", "")]),
                         ("no-tls.csv", [r for r in rows if r["tls"].startswith("no-tls")])):
        with open(os.path.join(OUT, name), "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=fields)
            w.writeheader()
            w.writerows(subset)
        print(f"wrote {OUT}/{name}: {len(subset)} rows", flush=True)


if __name__ == "__main__":
    main()
