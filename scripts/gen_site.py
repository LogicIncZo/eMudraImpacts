#!/usr/bin/env python3
"""Generate the GitHub Pages site (docs/) from the scan results.

Produces docs/index.html (self-contained, no external assets) with the
G3 (compromised intermediates) and G1 (emSign family) impact lists, and
copies the deliverable CSVs into docs/data/ for direct download.
"""
import csv, html, os, shutil, datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(ROOT)
os.makedirs("docs/data", exist_ok=True)

summary = list(csv.DictReader(open("results/impacted-domains-summary.csv")))
g1 = list(csv.DictReader(open("results/g1-impact-list.csv")))
g3 = list(csv.DictReader(open("results/g3-impact-list.csv")))
for f_ in ("impacted-domains-summary.csv", "g1-impact-list.csv", "g3-impact-list.csv"):
    shutil.copy(f"results/{f_}", f"docs/data/{f_}")
shutil.copy("results/impacted.csv", "docs/data/impacted-hosts.csv")
shutil.copy("data/gov-domains.txt", "docs/data/gov-domains.txt")

SCAN_DATE = "2026-10-24"
DOMS_SCANNED, HOSTS_CAND = 9670, 17166
TLS_OK = 6024
n_dom = len(summary)
n_host = len(g1) + len(g3)
n_expired = sum(int(r["expired_leaves"]) for r in summary)
n_direct = sum(1 for r in g1 if "legacy, direct" in r["g1_path"])
n_cross = sum(1 for r in g1 if "Root TLS CA" in r["g1_path"])
n_legacy = len(g1) - n_direct - n_cross

G3_IOCS = "EM DV TLS CA - G3B · EM OV TLS CA - G3B · EM EV TLS CA - G3B · EM DV TLS CA - G3C · EM OV TLS CA - G3C · EM EV TLS CA - G3C (+ EM OV CS CA - G3B/G3C, code-signing)"

# per-domain G1 paths (endpoint-level truth, joined for the table)
dom_paths = {}
for r in g1:
    dom_paths.setdefault(r["domain"], set()).add(r["g1_path"])

rows = []
for r in sorted(summary, key=lambda x: x["domain"]):
    dom = html.escape(r["domain"])
    paths = "; ".join(sorted(dom_paths.get(r["domain"], {"?"})))
    rows.append(
        f'<tr data-d="{dom}"><td><a href="https://{dom}/" rel="noopener">{dom}</a></td>'
        f'<td class="mono">{html.escape(paths)}</td>'
        f'<td class="mono">{html.escape(r["leaf_issuers"])}</td>'
        f'<td class="mono">{html.escape(r["attributed_roots"])}</td>'
        f'<td class="num">{r["impacted_hosts"]}</td>'
        f'<td class="num">{r["expired_leaves"] or ""}</td></tr>'
    )
table_rows = "\n".join(rows)

g3_block = (
    f'<div class="empty ok">✅ <strong>0 endpoints found</strong> across all {DOMS_SCANNED:,} scanned domains. '
    f"No Indian gov site is on the compromised intermediates, so the 2026-10-27 Chrome removal does not "
    f"hard-break any scanned gov site. The checked-for intermediates:<br><span class='mono'>{G3_IOCS}</span><br>"
    f"(<a href='data/g3-impact-list.csv'>g3-impact-list.csv</a> ships with headers only — kept as evidence of the negative result.)</div>"
    if not g3 else
    '<div style="overflow-x:auto"><table id="t3"><thead><tr><th>Host</th><th>Domain</th><th>Leaf issuer</th>'
    '<th>Compromised intermediate</th></tr></thead><tbody>' +
    "\n".join(f'<tr><td class="mono">{html.escape(r["host"])}</td><td>{html.escape(r["domain"])}</td>'
              f'<td class="mono">{html.escape(r["leaf_issuer"])}</td>'
              f'<td class="mono">{html.escape(r["compromised_intermediate"])}</td></tr>' for r in g3) +
    '</tbody></table></div>'
)

page = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>eMudhra Impact Tracker — Indian Government Websites on eMudhra/emSign TLS</title>
<meta name="description" content="G3 and G1 impact lists: Indian government (.gov.in / .nic.in) websites whose TLS certificates chain to eMudhra/emSign CAs affected by the October 2026 CA compromise and root removals.">
<style>
:root{{--bg:#0d1117;--fg:#e6edf3;--mut:#8b949e;--acc:#58a6ff;--warn:#f85149;--ok:#3fb950;--card:#161b22;--bd:#30363d}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--fg);font:16px/1.6 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}}
main{{max-width:1100px;margin:0 auto;padding:2rem 1.25rem 4rem}}
a{{color:var(--acc)}}
h1{{font-size:1.7rem;line-height:1.3;margin:.2rem 0}}
h2{{margin-top:2.2rem;border-bottom:1px solid var(--bd);padding-bottom:.3rem}}
h3{{margin-top:1.6rem}}
.lede{{color:var(--mut);font-size:1.05rem}}
.alert{{background:#3d1418;border:1px solid var(--warn);border-radius:8px;padding:.9rem 1.1rem;margin:1.4rem 0}}
.empty{{border:1px solid var(--bd);border-radius:8px;padding:.9rem 1.1rem;margin:1rem 0}}
.empty.ok{{background:#12261e;border-color:#2ea043}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:.8rem;margin:1.4rem 0}}
.card{{background:var(--card);border:1px solid var(--bd);border-radius:8px;padding:.8rem 1rem}}
.card .n{{font-size:1.6rem;font-weight:700}}
.card .l{{color:var(--mut);font-size:.82rem}}
.card.hot .n{{color:var(--warn)}}
.card.good .n{{color:var(--ok)}}
input#q{{width:100%;padding:.6rem .8rem;background:var(--card);border:1px solid var(--bd);border-radius:8px;color:var(--fg);font-size:1rem;margin:.5rem 0 .9rem}}
table{{border-collapse:collapse;width:100%;font-size:.9rem}}
th,td{{text-align:left;padding:.45rem .6rem;border-bottom:1px solid var(--bd);vertical-align:top}}
th{{color:var(--mut);position:sticky;top:0;background:var(--bg);cursor:pointer;user-select:none;white-space:nowrap}}
td.mono{{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:.8rem;color:var(--mut)}}
td.num{{text-align:right;font-variant-numeric:tabular-nums}}
.count{{color:var(--mut)}}
code,.mono{{font-family:ui-monospace,Menlo,Consolas,monospace}}
code{{background:var(--card);padding:.1rem .35rem;border-radius:4px;font-size:.85em}}
footer{{color:var(--mut);font-size:.85rem;border-top:1px solid var(--bd);margin-top:3rem;padding-top:1rem}}
li{{margin:.25rem 0}}
</style>
</head>
<body>
<main>
<p class="lede">Independent tracking by <a href="https://github.com/LogicIncZo">LogicIncZo</a> · scan date {SCAN_DATE} · <a href="https://github.com/LogicIncZo/eMudraImpacts">repo</a></p>
<h1>eMudhra Impact Tracker</h1>
<p class="lede">Indian government websites (<code>.gov.in</code> / <code>.nic.in</code>) whose TLS certificates chain to
eMudhra / emSign CAs affected by the <strong>October 2026 eMudhra CA compromise</strong> and the removal of
<code>emSign</code> G3 roots from browser &amp; OS trust stores. Impact is split into two lists:</p>
<ul>
<li><strong><a href="#g3">G3 impact list</a></strong> — endpoints on the 8 compromised intermediates (dies with the 2026-10-27 Chrome removal). <strong>None found.</strong></li>
<li><strong><a href="#g1">G1 impact list</a></strong> — endpoints on eMudhra's G1 family (still trusted today; reissue on a planned timeline). <strong>{n_dom} domains / {n_host} endpoints.</strong></li>
</ul>

<div class="alert"><strong>⏰ 2026-10-27:</strong> Chrome removes <code>emSign ECC Root CA - G3</code> (root store v43).
Microsoft has blocked the 8 compromised intermediates since 2026-10-20; Mozilla removed the G3 root from NSS the same day.
Legacy <code>emSign Root CA - G1</code> is <em>not</em> removed yet — Chrome is evaluating it, and eMudhra is migrating affected customers onto it.</div>

<div class="cards">
<div class="card"><div class="n">{DOMS_SCANNED:,}</div><div class="l">gov domains scanned</div></div>
<div class="card"><div class="n">{TLS_OK:,}</div><div class="l">endpoints with TLS</div></div>
<div class="card good"><div class="n">0</div><div class="l">G3 / compromised intermediates</div></div>
<div class="card hot"><div class="n">{n_dom}</div><div class="l">G1 domains (watch-list)</div></div>
<div class="card hot"><div class="n">{n_host}</div><div class="l">G1 endpoints (hosts)</div></div>
<div class="card"><div class="n">{n_expired}</div><div class="l">G1 leaves already expired</div></div>
</div>

<h2 id="g3">G3 impact list — compromised intermediates</h2>
<p>These chains break immediately: Microsoft blocks the intermediates since 2026-10-20, Mozilla NSS dropped
<code>emSign ECC Root CA - G3</code> the same day, and Chrome removes the root on 2026-10-27. The Sectigo AAA cross-sign
was revoked 2026-10-19, so there is no fallback path.</p>
{g3_block}

<h2 id="g1">G1 impact list — emSign G1 family</h2>
<p>{n_dom} domains serving certificates that terminate at <code>emSign Root CA - G1</code> (legacy root, present in all
major stores) or at <code>emSign Root TLS CA - G1</code> (2024, Microsoft-only root cross-signed by legacy G1).
All these sites <strong>work today</strong>. They break if Chrome/Mozilla remove legacy <code>emSign Root CA - G1</code>
(under evaluation) — and eMudhra is exiting the public TLS business regardless, so reissue from another CA is the
recommended action, planned rather than emergency.</p>

<div class="cards">
<div class="card"><div class="n">{n_direct}</div><div class="l">endpoints — legacy G1, direct (<code>emSign SSL CA - G1</code>)</div></div>
<div class="card"><div class="n">{n_cross}</div><div class="l">endpoints — via <code>emSign Root TLS CA - G1</code> (MS-only) + legacy cross-sign (<code>EM * TLS CA - G2A-1</code>)</div></div>
<div class="card"><div class="n">{n_legacy}</div><div class="l">endpoints — other legacy eMudhra root</div></div>
</div>

<h3>Domains ({n_dom})</h3>
<p class="count" id="cnt">showing all {n_dom}</p>
<input id="q" type="search" placeholder="filter by domain / issuer / root…" autofocus>
<div style="overflow-x:auto">
<table id="t">
<thead><tr>
<th data-k="domain">Domain ▾</th><th data-k="paths">G1 trust path(s)</th><th data-k="leaf_issuers">Leaf issuer(s)</th>
<th data-k="attributed_roots">Chain root(s)</th><th data-k="impacted_hosts">Hosts</th><th data-k="expired_leaves">Expired</th>
</tr></thead>
<tbody>
{table_rows}
</tbody>
</table>
</div>

<h2>Downloads &amp; evidence</h2>
<ul>
<li><a href="data/g1-impact-list.csv">g1-impact-list.csv</a> — all {n_host} G1 endpoints with trust path, chain, status</li>
<li><a href="data/g3-impact-list.csv">g3-impact-list.csv</a> — G3/compromised-intermediate list (currently header-only)</li>
<li><a href="data/impacted-domains-summary.csv">impacted-domains-summary.csv</a> — one row per domain (table above)</li>
<li><a href="data/impacted-hosts.csv">impacted-hosts.csv</a> — combined raw impacted-host scan output</li>
<li><a href="data/gov-domains.txt">gov-domains.txt</a> — the {DOMS_SCANNED:,}-domain scan universe</li>
<li>Per-host certificate chains: <a href="https://github.com/LogicIncZo/eMudraImpacts/tree/main/results/chains">results/chains/ in the repo</a> ·
scanner: <a href="https://github.com/LogicIncZo/eMudraImpacts/tree/main/scripts">scripts/</a> (openssl-based, re-runnable)</li>
</ul>

<h2>Methodology</h2>
<ul>
<li>Universe: registry dump of {DOMS_SCANNED:,} registrable <code>.gov.in</code>/<code>.nic.in</code> domains; per domain the apex
and <code>www.</code> were probed on :443 (fallback :8443), plus a common-prefix vhost probe (portal/services/sso/apps/…) over impacted domains.</li>
<li>Chains captured with <code>openssl s_client -showcerts</code>; a host is flagged when its leaf issuer or any presented
chain element matches the compromised intermediates or carries eMudhra/emSign branding.</li>
<li>G1 paths: <code>emSign SSL CA - G1</code> leaves chain directly to legacy <code>emSign Root CA - G1</code>;
<code>EM * TLS CA - G2A-1</code> leaves chain to the Microsoft-only <code>emSign Root TLS CA - G1</code>, cross-signed by legacy G1.</li>
<li>Limitations: HTTPS on 443/8443 only; full CT-based vhost enumeration is pending (crt.sh rate limits); universe is the
registry snapshot, not a live registry.</li>
</ul>

<h2>If you operate one of these sites</h2>
<ol>
<li>Check your chain: <code>openssl s_client -connect yourhost:443 -servername yourhost -showcerts | openssl x509 -noout -issuer</code>.</li>
<li>Reissue from a CA outside the eMudhra/emSign family and redeploy. Update clients too (ca-certificates, certifi ≥ 2026.10.19, Go ≥ 1.27.3, Node ≥ 22.23.4; rebuild containers older than 2026-10-20).</li>
<li>Indian gov sites on CCA-India chains (NIC sub-CAs) are a separate matter — those roots are not in public trust stores and are unaffected by this incident.</li>
</ol>

<footer>
Independent research; certificate chains are public TLS observations, not vulnerability disclosures.
Incident background: <a href="https://emudhra.we-have-a-problem.com/">researcher incident page</a> ·
Mozilla Bugzilla <a href="https://bugzilla.mozilla.org/show_bug.cgi?id=2083449">2083449</a> ·
generated {datetime.date.today().isoformat()}
</footer>
</main>
<script>
const q=document.getElementById('q'),rows=[...document.querySelectorAll('#t tbody tr')],cnt=document.getElementById('cnt');
q.addEventListener('input',()=>{{const s=q.value.toLowerCase();let v=0;
for(const r of rows){{const hit=!s||r.dataset.d.includes(s)||r.textContent.toLowerCase().includes(s);r.hidden=!hit;if(hit)v++;}}
cnt.textContent=`showing ${{v}} of {n_dom}`;}});
document.querySelectorAll('#t th').forEach(th=>th.addEventListener('click',()=>{{
const tb=document.querySelector('#t tbody'),i=[...th.parentElement.children].indexOf(th);
const num=th.dataset.k==='impacted_hosts'||th.dataset.k==='expired_leaves';
[...tb.querySelectorAll('tr')].sort((a,b)=>{{const x=a.children[i].textContent.trim(),y=b.children[i].textContent.trim();
return (num?((+x||0)-(+y||0)):x.localeCompare(y))*(th.asc?-1:1);}}).forEach(r=>tb.appendChild(r));
th.asc=!th.asc;}});
</script>
</body>
</html>
"""
with open("docs/index.html", "w") as f:
    f.write(page)
print(f"docs/index.html written ({n_dom} G1 domains, {n_host} G1 hosts, {len(g3)} G3 hosts)")
