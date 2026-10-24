#!/usr/bin/env python3
"""Generate the GitHub Pages site (docs/) from the scan results.

Produces docs/index.html (self-contained, no external assets) and copies the
deliverable CSVs into docs/data/ for direct download.
"""
import csv, html, os, shutil, datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(ROOT)
os.makedirs("docs/data", exist_ok=True)

summary = list(csv.DictReader(open("results/impacted-domains-summary.csv")))
shutil.copy("results/impacted-domains-summary.csv", "docs/data/impacted-domains-summary.csv")
shutil.copy("results/impacted.csv", "docs/data/impacted-hosts.csv")
shutil.copy("data/gov-domains.txt", "docs/data/gov-domains.txt")

SCAN_DATE = "2026-10-24"
DOMS_SCANNED, HOSTS_CAND = 9670, 17166
TLS_OK, NO_TLS = 6024, 11142
n_dom = len(summary)
n_host = sum(int(r["impacted_hosts"]) for r in summary)
n_expired = sum(int(r["expired_leaves"]) for r in summary)

rows = []
for r in sorted(summary, key=lambda x: x["domain"]):
    dom = html.escape(r["domain"])
    rows.append(
        f'<tr data-d="{dom}"><td><a href="https://{dom}/" rel="noopener">{dom}</a></td>'
        f'<td>{html.escape(r["verdict"])}</td>'
        f'<td class="mono">{html.escape(r["leaf_issuers"])}</td>'
        f'<td class="mono">{html.escape(r["attributed_roots"])}</td>'
        f'<td class="num">{r["impacted_hosts"]}</td>'
        f'<td class="num">{r["expired_leaves"] or ""}</td></tr>'
    )
table_rows = "\n".join(rows)

page = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>eMudhra Impact Tracker — Indian Government Websites on eMudhra/emSign TLS</title>
<meta name="description" content="Inventory of Indian government (.gov.in / .nic.in) websites whose TLS certificates chain to eMudhra/emSign roots affected by the October 2026 CA compromise and root removals.">
<style>
:root{{--bg:#0d1117;--fg:#e6edf3;--mut:#8b949e;--acc:#58a6ff;--warn:#f85149;--ok:#3fb950;--card:#161b22;--bd:#30363d}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--fg);font:16px/1.6 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}}
main{{max-width:1100px;margin:0 auto;padding:2rem 1.25rem 4rem}}
a{{color:var(--acc)}}
h1{{font-size:1.7rem;line-height:1.3;margin:.2rem 0}}
h2{{margin-top:2.2rem;border-bottom:1px solid var(--bd);padding-bottom:.3rem}}
.lede{{color:var(--mut);font-size:1.05rem}}
.alert{{background:#3d1418;border:1px solid var(--warn);border-radius:8px;padding:.9rem 1.1rem;margin:1.4rem 0}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:.8rem;margin:1.4rem 0}}
.card{{background:var(--card);border:1px solid var(--bd);border-radius:8px;padding:.8rem 1rem}}
.card .n{{font-size:1.7rem;font-weight:700}}
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
<code>emSign</code> G3 roots from browser &amp; OS trust stores.</p>

<div class="alert"><strong>⏰ 2026-10-27:</strong> Chrome removes <code>emSign ECC Root CA - G3</code> (root store v43).
Microsoft has blocked the 8 compromised intermediates since 2026-10-20; Mozilla removed the G3 root from NSS the same day.
Sites on the compromised intermediates are already failing; sites on the G1 family (this inventory) still work but need reissue on a planned timeline.</div>

<div class="cards">
<div class="card"><div class="n">{DOMS_SCANNED:,}</div><div class="l">gov domains scanned</div></div>
<div class="card"><div class="n">{TLS_OK:,}</div><div class="l">endpoints with TLS</div></div>
<div class="card hot"><div class="n">{n_dom}</div><div class="l">domains on eMudhra/emSign TLS</div></div>
<div class="card hot"><div class="n">{n_host}</div><div class="l">impacted endpoints (hosts)</div></div>
<div class="card good"><div class="n">0</div><div class="l">on the 8 compromised intermediates</div></div>
<div class="card"><div class="n">{n_expired}</div><div class="l">leaves already expired</div></div>
</div>

<h2>The affected hierarchy, in one paragraph</h2>
<p>Eight eMudhra intermediate CA keys were compromised (<code>EM DV/OV/EV TLS CA - G3B/G3C</code> plus two code-signing CAs).
They were cross-signed by <code>emSign ECC Root CA - G3</code> (trusted by Chrome, Mozilla, Microsoft) and by a Sectigo
<code>AAA Certificate Services</code> cross-sign (now revoked/removed). This scan found <strong>no</strong> Indian gov site on those
intermediates. What it did find: {n_dom} gov domains serving certificates from eMudhra's <strong>G1 family</strong>
(<code>EM * TLS CA - G2A-1</code> → <code>emSign Root TLS CA - G1</code> → legacy <code>emSign Root CA - G1</code>, and
<code>emSign SSL CA - G1</code> → <code>emSign Root CA - G1</code>). That family remains trusted today, but eMudhra is exiting the
public TLS business and Chrome is evaluating G1's future — reissue from another CA is the safe move.</p>

<h2>Impacted domains ({n_dom})</h2>
<p class="count" id="cnt">showing all {n_dom}</p>
<input id="q" type="search" placeholder="filter by domain / issuer / root…" autofocus>
<div style="overflow-x:auto">
<table id="t">
<thead><tr>
<th data-k="domain">Domain ▾</th><th data-k="verdict">Verdict</th><th data-k="leaf_issuers">Leaf issuer(s)</th>
<th data-k="attributed_roots">Chain root(s)</th><th data-k="impacted_hosts">Hosts</th><th data-k="expired_leaves">Expired</th>
</tr></thead>
<tbody>
{table_rows}
</tbody>
</table>
</div>

<h2>Downloads &amp; evidence</h2>
<ul>
<li><a href="data/impacted-domains-summary.csv">impacted-domains-summary.csv</a> — one row per domain (this table)</li>
<li><a href="data/impacted-hosts.csv">impacted-hosts.csv</a> — all {n_host} impacted endpoints with full chain metadata</li>
<li><a href="data/gov-domains.txt">gov-domains.txt</a> — the {DOMS_SCANNED:,}-domain scan universe</li>
<li>Per-host certificate chains: <a href="https://github.com/LogicIncZo/eMudraImpacts/tree/main/results/chains">results/chains/ in the repo</a></li>
<li>Scanner &amp; generator: <a href="https://github.com/LogicIncZo/eMudraImpacts/tree/main/scripts">scripts/</a> (openssl-based, re-runnable)</li>
</ul>

<h2>Methodology</h2>
<ul>
<li>Universe: registry dump of {DOMS_SCANNED:,} registrable <code>.gov.in</code>/<code>.nic.in</code> domains; per domain the apex
and <code>www.</code> were probed on :443 (fallback :8443), plus a common-prefix vhost probe (portal/services/sso/apps/…) over impacted domains.</li>
<li>Chains captured with <code>openssl s_client -showcerts</code>; a host is flagged when its leaf issuer or any presented
chain element matches the compromised intermediates or carries eMudhra/emSign branding.</li>
<li>Verdict <em>G1-FAMILY (watch-list)</em> = issued under <code>emSign Root CA - G1</code> / <code>emSign Root TLS CA - G1</code>;
<em>CONFIRMED-COMPROMISED-INT</em> = one of the 8 compromised intermediates (none found).</li>
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
const tb=document.querySelector('#t tbody'),k=th.dataset.k,i=[...th.parentElement.children].indexOf(th);
const num=k.includes('hosts')||k.includes('expired');
[...tb.querySelectorAll('tr')].sort((a,b)=>{{const x=a.children[i].textContent.trim(),y=b.children[i].textContent.trim();
return (num?((+x||0)-(+y||0)):x.localeCompare(y))*(th.asc?-1:1);}}).forEach(r=>tb.appendChild(r));
th.asc=!th.asc;}});
</script>
</body>
</html>
"""
with open("docs/index.html", "w") as f:
    f.write(page)
print(f"docs/index.html written ({n_dom} domains, {n_host} hosts)")
