"""Static dashboard: agent graph, headline metrics, LOAO, confusion, filterable verdict log.

  python -m src.dashboard      # -> outputs/dashboard.html (self-contained, open in a browser)
"""
import json
from html import escape

import pandas as pd

from src.config import BENIGN, CLASSES, DASHBOARD_HTML, EVAL_RESULTS, LABEL_COL, METRICS, OUTPUTS_DIR
from src.viz import grouped_hbar, heat_table, legend

LOG_COLS = ["record_id", LABEL_COL, "a1_class", "a1_conf", "a2_score", "a2_anomalous",
            "final_class", "status", "evidence_strength", "policy", "rationale"]


def verdict_sample(r: pd.DataFrame, per_status: int = 60, seed: int = 42) -> pd.DataFrame:
    """Every misclassified flow + up to `per_status` flows per status (stratified by true class)."""
    wrong = r[r["final_class"] != r[LABEL_COL]]
    parts = [wrong]
    for _, g in r.groupby("status"):
        k = max(per_status // g[LABEL_COL].nunique(), 1)
        # groupby.apply drops the grouping column in pandas 3; shuffle + head keeps it
        parts.append(g.sample(frac=1, random_state=seed).groupby(LABEL_COL).head(k))
    out = pd.concat(parts).drop_duplicates("record_id")
    out = out[LOG_COLS].copy()
    out["a1_conf"] = out["a1_conf"].round(3)
    out["a2_score"] = out["a2_score"].round(3)
    out["correct"] = out["final_class"] == out[LABEL_COL]
    return out


def agent_graph(m: dict) -> str:
    n = m["all"]["n"]
    pol = m["policy_counts"]
    boxes = [  # x, y, w, title, subtitle
        (10, 95, 120, "Prep", "71 features"),
        (190, 25, 170, "A1 Threat", "LightGBM · calibrated"),
        (190, 165, 170, "A2 Anomaly", "IsolationForest · benign"),
        (430, 95, 170, "A3 Fusion", "rule table"),
        (650, 95, 170, "Policy", "ALLOW · BLOCK · REVIEW"),
    ]
    svg = ['<svg viewBox="0 0 830 240" class="graph" role="img" aria-label="agent graph">',
           '<defs><marker id="arr" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" '
           'orient="auto"><path d="M0,0 L10,5 L0,10 z" fill="var(--muted)"/></marker></defs>']
    for a, b in [((130, 120), (190, 50)), ((130, 120), (190, 190)), ((360, 50), (430, 115)),
                 ((360, 190), (430, 125)), ((600, 120), (650, 120))]:
        svg.append(f'<line x1="{a[0]}" y1="{a[1]}" x2="{b[0]}" y2="{b[1]}" class="edge" marker-end="url(#arr)"/>')
    for x, y, w, t, s in boxes:
        svg.append(f'<rect x="{x}" y="{y}" width="{w}" height="50" rx="10" class="node"/>'
                   f'<text x="{x + w / 2}" y="{y + 22}" text-anchor="middle" class="nt">{escape(t)}</text>'
                   f'<text x="{x + w / 2}" y="{y + 39}" text-anchor="middle" class="ns">{escape(s)}</text>')
    svg.append(f'<text x="70" y="170" text-anchor="middle" class="ns">{n:,} flows</text>')
    svg.append(f'<text x="745" y="170" text-anchor="middle" class="ns">BLOCK {pol.get("BLOCK", 0):,}</text>'
               f'<text x="745" y="186" text-anchor="middle" class="ns">ALLOW {pol.get("ALLOW", 0):,}</text>'
               f'<text x="745" y="202" text-anchor="middle" class="ns">REVIEW {pol.get("REVIEW", 0):,}</text>')
    svg.append(f'<text x="515" y="170" text-anchor="middle" class="ns">overrides {m["all"]["override_count"]:,}</text>')
    return "".join(svg) + "</svg>"


def kpi(label: str, value: str, note: str = "") -> str:
    return f'<div class="kpi"><div class="kl">{escape(label)}</div><div class="kv">{escape(value)}</div>' \
           f'<div class="kn">{escape(note)}</div></div>'


def build() -> str:
    m = json.loads(METRICS.read_text())
    r = pd.read_parquet(EVAL_RESULTS)
    loao = {c: json.loads(p.read_text()) for c in CLASSES if (p := OUTPUTS_DIR / f"loao_{c}.json").exists()}
    a, u = m["all"], m["unseen_in_train"]

    kpis = "".join([
        kpi("Macro-F1 (fused)", f'{a["fused"]["macro_f1"]:.6f}', f'A1 alone {a["a1"]["macro_f1"]:.6f}'),
        kpi("Unseen-in-train macro-F1", f'{u["fused"]["macro_f1"]:.6f}', f'{u["n"]:,} flows'),
        kpi("Accuracy (fused)", f'{a["fused"]["accuracy"]:.6f}', f'{a["n"]:,} flows'),
        kpi("Fusion overrides", f'{a["override_count"]:,}', f'agreement {a["agreement_rate"]:.2%}'),
        kpi("A2 ROC-AUC", f'{m["a2"]["roc_auc_attack_vs_benign"]:.3f}', "attack vs benign, no labels"),
        kpi("Throughput", f'{m.get("throughput", {}).get("flows_per_sec", 0):,.0f}/s', "full pipeline"),
    ])

    f1_rows = "".join(
        f'<tr><td>{c}</td><td>{a["a1"]["per_class_f1"][c]:.6f}</td><td>{a["fused"]["per_class_f1"][c]:.6f}</td>'
        f'<td>{m["a2"]["flag_rate_per_class"].get(c, 0):.2%}</td></tr>' for c in CLASSES)

    if loao:
        held = list(loao)
        loao_html = legend(["A1 detects", "Fused detects", "A2 flags"]) + grouped_hbar(held, {
            "A1 detects": [loao[c]["a1_detect_rate"] for c in held],
            "Fused detects": [loao[c]["fused_detect_rate"] for c in held],
            "A2 flags": [loao[c]["a2_flag_rate"] for c in held],
        })
        loao_table = "".join(
            f'<tr><td>{c}</td><td>{loao[c]["n_holdout_eval"]:,}</td><td>{loao[c]["a1_detect_rate"]:.2%}</td>'
            f'<td>{loao[c]["fused_detect_rate"]:.2%}</td><td>{loao[c]["a2_flag_rate"]:.2%}</td>'
            f'<td>{escape(", ".join(f"{k} {v:,}" for k, v in loao[c]["a1_predicted_as"].items()))}</td></tr>'
            for c in held)
        loao_html += ('<details><summary>Table view</summary><table class="t"><tr><th>held out</th><th>flows</th>'
                      '<th>A1 detects</th><th>fused detects</th><th>A2 flags</th><th>A1 called it</th></tr>'
                      f'{loao_table}</table></details>')
    else:
        loao_html = '<p class="muted">Run <code>python scripts/loao.py --holdout ALL</code> to fill this.</p>'

    status_rows = "".join(
        f"<tr><th>{escape(cls)}</th>" + "".join(f"<td>{row.get(s, 0):,}</td>" for s in sorted(m["status_counts"])) + "</tr>"
        for cls, row in m["status_by_class"].items())
    status_head = "".join(f"<th>{escape(s)}</th>" for s in sorted(m["status_counts"]))

    log = verdict_sample(r)
    log_json = log.to_json(orient="records")
    opts = lambda col: "".join(f"<option>{escape(str(v))}</option>" for v in sorted(log[col].unique()))

    return TEMPLATE.format(
        graph=agent_graph(m), kpis=kpis, f1_rows=f1_rows, loao=loao_html,
        cm_a1=heat_table(m["confusion"]["labels"], m["confusion"]["a1"]),
        cm_fused=heat_table(m["confusion"]["labels"], m["confusion"]["fused"]),
        status_head=status_head, status_rows=status_rows,
        n_log=len(log), n_wrong=int((~log["correct"]).sum()),
        opt_status=opts("status"), opt_label=opts(LABEL_COL), opt_policy=opts("policy"),
        log_json=log_json, benign=BENIGN,
    )


TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CyberSentinel Dashboard</title>
<style>
:root {{ color-scheme: light; --bg:#f9f9f7; --surface:#fcfcfb; --ink:#0b0b0b; --ink2:#52514e; --muted:#898781;
  --grid:#e1e0d9; --base:#c3c2b7; --ring:rgba(11,11,11,.10); --s1:#2a78d6; --s2:#eb6834; --s3:#1baf7a;
  --good:#006300; --bad:#c62828; }}
@media (prefers-color-scheme: dark) {{ :root:not([data-theme="light"]) {{ color-scheme: dark; --bg:#0d0d0d;
  --surface:#1a1a19; --ink:#f0efec; --ink2:#c3c2b7; --grid:#2c2c2a; --base:#383835; --ring:rgba(255,255,255,.10);
  --s1:#3987e5; --s2:#d95926; --s3:#199e70; --good:#0ca30c; --bad:#e66767; }} }}
:root[data-theme="dark"] {{ color-scheme: dark; --bg:#0d0d0d; --surface:#1a1a19; --ink:#f0efec; --ink2:#c3c2b7;
  --grid:#2c2c2a; --base:#383835; --ring:rgba(255,255,255,.10); --s1:#3987e5; --s2:#d95926; --s3:#199e70;
  --good:#0ca30c; --bad:#e66767; }}
* {{ box-sizing: border-box; }}
body {{ margin:0; background:var(--bg); color:var(--ink); font:14px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif; }}
main {{ max-width:1200px; margin:0 auto; padding:24px 16px 64px; }}
h1 {{ font-size:26px; margin:0 0 4px; }} h2 {{ font-size:17px; margin:0 0 12px; }}
.sub, .muted {{ color:var(--ink2); }}
.card {{ background:var(--surface); border:1px solid var(--ring); border-radius:14px; padding:18px; margin-top:16px; }}
.kpis {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(170px,1fr)); gap:12px; margin-top:16px; }}
.kpi {{ background:var(--surface); border:1px solid var(--ring); border-radius:12px; padding:14px; }}
.kl {{ color:var(--ink2); font-size:12px; }} .kv {{ font-size:24px; font-weight:650; font-variant-numeric:tabular-nums; }}
.kn {{ color:var(--muted); font-size:12px; }}
.grid2 {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(min(100%,460px),1fr)); gap:16px; }}
.graph, .chart {{ width:100%; height:auto; display:block; }}
.node {{ fill:var(--surface); stroke:var(--base); stroke-width:1.5; }}
.nt {{ fill:var(--ink); font-weight:600; font-size:14px; }} .ns {{ fill:var(--ink2); font-size:11.5px; }}
.edge {{ stroke:var(--muted); stroke-width:2; }}
.lbl {{ fill:var(--ink2); font-size:12.5px; }} .val {{ fill:var(--ink); font-size:12px; font-variant-numeric:tabular-nums; }}
.axis {{ stroke:var(--base); }}
.legend {{ display:flex; gap:16px; flex-wrap:wrap; margin-bottom:8px; color:var(--ink2); font-size:12.5px; }}
.legend i {{ display:inline-block; width:10px; height:10px; border-radius:3px; margin-right:6px; vertical-align:-1px; }}
.scroll {{ overflow-x:auto; }}
table {{ border-collapse:collapse; width:100%; font-variant-numeric:tabular-nums; }}
th, td {{ padding:6px 8px; text-align:right; border-bottom:1px solid var(--grid); white-space:nowrap; }}
th:first-child, td:first-child {{ text-align:left; }} th {{ color:var(--ink2); font-weight:600; font-size:12.5px; }}
.heat td {{ text-align:center; border:2px solid var(--surface); border-radius:4px; }}
details {{ margin-top:10px; }} summary {{ cursor:pointer; color:var(--ink2); }}
.filters {{ display:flex; gap:8px; flex-wrap:wrap; margin-bottom:10px; }}
select, input {{ background:var(--bg); color:var(--ink); border:1px solid var(--ring); border-radius:8px; padding:6px 8px; font:inherit; }}
input {{ flex:1; min-width:160px; }}
#log td.r {{ text-align:left; white-space:normal; min-width:320px; color:var(--ink2); }}
.ok {{ color:var(--good); }} .bad {{ color:var(--bad); font-weight:600; }}
.pill {{ display:inline-block; padding:1px 8px; border-radius:99px; border:1px solid var(--ring); font-size:12px; }}
code {{ background:var(--bg); padding:1px 5px; border-radius:5px; }}
</style></head>
<body><main>
<h1>CyberSentinel</h1>
<div class="sub">Multi-agent intrusion detection on CICIDS2017 eval. Offline replay; policy is simulated.</div>

<div class="kpis">{kpis}</div>

<section class="card"><h2>Agent graph</h2>{graph}</section>

<div class="grid2">
<section class="card"><h2>Leave-one-attack-out: catching an attack type never trained on</h2>
<p class="muted">A1 is retrained without the held-out class; share of that class's eval flows each agent catches.</p>
{loao}</section>
<section class="card"><h2>Per-class F1 and A2 flag rate</h2>
<div class="scroll"><table class="t"><tr><th>class</th><th>A1 F1</th><th>fused F1</th><th>A2 flags</th></tr>{f1_rows}</table></div>
<h2 style="margin-top:18px">Fusion status by true class</h2>
<div class="scroll"><table class="t"><tr><th>class</th>{status_head}</tr>{status_rows}</table></div>
</section>
</div>

<div class="grid2">
<section class="card"><h2>Confusion: A1 alone</h2><div class="scroll">{cm_a1}</div></section>
<section class="card"><h2>Confusion: fused</h2><div class="scroll">{cm_fused}</div></section>
</div>

<section class="card"><h2>Verdict log</h2>
<p class="muted">{n_log} sampled flows: every misclassified flow ({n_wrong}) plus a stratified sample per status.</p>
<div class="filters">
<select id="fs"><option value="">all statuses</option>{opt_status}</select>
<select id="fl"><option value="">all true classes</option>{opt_label}</select>
<select id="fp"><option value="">all policies</option>{opt_policy}</select>
<select id="fc"><option value="">correct + wrong</option><option value="0">wrong only</option><option value="1">correct only</option></select>
<input id="fq" placeholder="search record_id or rationale">
</div>
<div class="scroll"><table id="log"><thead><tr><th>record_id</th><th>true</th><th>A1</th><th>conf</th><th>A2 score</th>
<th>final</th><th>status</th><th>strength</th><th>policy</th><th>rationale</th></tr></thead><tbody></tbody></table></div>
<p class="muted" id="cnt"></p>
</section>
</main>
<script>
const LOG = {log_json};
const $ = id => document.getElementById(id);
const esc = s => String(s).replace(/[&<>"]/g, c => ({{"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}}[c]));
function render() {{
  const s=$("fs").value, l=$("fl").value, p=$("fp").value, c=$("fc").value, q=$("fq").value.toLowerCase();
  const rows = LOG.filter(r => (!s||r.status===s) && (!l||r.label===l) && (!p||r.policy===p)
    && (c===""||String(+r.correct)===c) && (!q||r.record_id.toLowerCase().includes(q)||r.rationale.toLowerCase().includes(q)));
  $("log").tBodies[0].innerHTML = rows.slice(0, 400).map(r => `<tr>
    <td>${{esc(r.record_id)}}</td><td>${{esc(r.label)}}</td><td>${{esc(r.a1_class)}}</td><td>${{r.a1_conf.toFixed(3)}}</td>
    <td>${{r.a2_score.toFixed(3)}}${{r.a2_anomalous?" ⚑":""}}</td>
    <td class="${{r.correct?"ok":"bad"}}">${{r.correct?"✓":"✗"}} ${{esc(r.final_class)}}</td>
    <td><span class="pill">${{esc(r.status)}}</span></td><td>${{esc(r.evidence_strength)}}</td><td>${{esc(r.policy)}}</td>
    <td class="r">${{esc(r.rationale)}}</td></tr>`).join("");
  $("cnt").textContent = `${{rows.length}} of ${{LOG.length}} shown` + (rows.length>400?" (first 400 rendered)":"");
}}
["fs","fl","fp","fc","fq"].forEach(id => $(id).addEventListener("input", render));
render();
</script></body></html>
"""


def main() -> None:
    DASHBOARD_HTML.write_text(build())
    print(f"-> {DASHBOARD_HTML}")


if __name__ == "__main__":
    main()
