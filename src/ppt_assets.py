"""Slide-ready PNGs (16:9) for the presentation.

  python -m src.ppt_assets     # -> outputs/ppt/*.png
"""
import json
import shutil

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from matplotlib.patches import FancyBboxPatch

from src.config import (BENIGN, CLASSES, CONFUSION_A1_PNG, CONFUSION_FUSED_PNG, EVAL_RESULTS, LABEL_COL,
                        METRICS, OUTPUTS_DIR, PPT_DIR)
from src.viz import BASE, INK, INK2, MUTED, SERIES, SURFACE, mpl_style

S1, S2, S3 = (c[0] for c in SERIES)
SIZE, DPI = (16, 9), 120  # 1920x1080


def save(fig, name: str) -> None:
    fig.savefig(PPT_DIR / name, dpi=DPI, bbox_inches="tight", pad_inches=0.4)
    plt.close(fig)
    print(f"  {name}")


def architecture() -> None:
    fig, ax = plt.subplots(figsize=SIZE)
    ax.set_xlim(0, 17.2), ax.set_ylim(0, 9), ax.axis("off")
    ax.grid(False)
    X0, XP, XA, X3, XO = 0.2, 3.6, 7.0, 10.6, 14.0
    nodes = {  # name: (x, y, title, subtitle, accent)
        "data": (X0, 3.9, "Flow parquet", "CICIDS2017 · 78 features", BASE),
        "prep": (XP, 3.9, "Prep", "train-only stats · 71 feats", BASE),
        "a1": (XA, 6.0, "A1 Threat Detector", "LightGBM · calibrated", S1),
        "a2": (XA, 1.8, "A2 Anomaly Agent", "IsolationForest · BENIGN only", S3),
        "a3": (X3, 3.9, "A3 Evidence Fusion", "rule table · rationale", S2),
        "pol": (XO, 3.9, "Policy", "ALLOW · BLOCK · REVIEW", BASE),
    }
    w, h = 3.0, 1.3
    for x, y, t, s, accent in nodes.values():
        ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.18",
                                    fc=SURFACE, ec=accent, lw=2.5))
        ax.text(x + w / 2, y + h * 0.62, t, ha="center", va="center", fontsize=14, weight="bold", color=INK)
        ax.text(x + w / 2, y + h * 0.28, s, ha="center", va="center", fontsize=11, color=INK2)

    def arrow(a, b):
        ax.annotate("", xy=b, xytext=a, arrowprops=dict(arrowstyle="-|>", color=MUTED, lw=2, mutation_scale=18))

    mid = h / 2
    arrow((X0 + w, 3.9 + mid), (XP, 3.9 + mid))
    arrow((XP + w, 3.9 + mid + 0.2), (XA, 6.0 + mid))
    arrow((XP + w, 3.9 + mid - 0.2), (XA, 1.8 + mid))
    arrow((XA + w, 6.0 + mid), (X3 + w / 2, 3.9 + h))
    arrow((XA + w, 1.8 + mid), (X3 + w / 2, 3.9))
    arrow((X3 + w, 3.9 + mid), (XO, 3.9 + mid))
    # edge labels sit beside the arrows, clear of the boxes
    ax.text(X3 + w / 2 + 0.3, 6.0 + mid, "class · conf · top-2", fontsize=11, color=INK2, va="center")
    ax.text(X3 + w / 2 + 0.3, 1.8 + mid, "score · flag · robust-z", fontsize=11, color=INK2, va="center")
    ax.text(X0, 8.4, "CyberSentinel architecture", fontsize=22, weight="bold", color=INK)
    ax.text(X0, 7.9, "Two independent agents, one transparent fusion step, an explainable policy",
            fontsize=13, color=INK2)
    save(fig, "01_architecture.png")


def headline(m: dict) -> None:
    a, u = m["all"], m["unseen_in_train"]
    tiles = [
        ("Macro-F1 (fused)", f'{a["fused"]["macro_f1"]:.4f}', f'A1 alone {a["a1"]["macro_f1"]:.4f}'),
        ("Unseen-in-train macro-F1", f'{u["fused"]["macro_f1"]:.4f}', f'{u["n"]:,} flows'),
        ("A2 ROC-AUC", f'{m["a2"]["roc_auc_attack_vs_benign"]:.3f}', "never sees attack labels"),
        ("Throughput", f'{m.get("throughput", {}).get("flows_per_sec", 0):,.0f}/s', "full 3-agent pipeline"),
    ]
    fig, ax = plt.subplots(figsize=(16, 5))
    ax.set_xlim(0, 16), ax.set_ylim(0, 5), ax.axis("off")
    ax.grid(False)
    for i, (label, value, note) in enumerate(tiles):
        x = 0.2 + i * 4
        ax.add_patch(FancyBboxPatch((x, 0.5), 3.6, 3.6, boxstyle="round,pad=0.02,rounding_size=0.2",
                                    fc=SURFACE, ec=BASE, lw=1.5))
        ax.text(x + 0.3, 3.5, label, fontsize=14, color=INK2)
        ax.text(x + 0.3, 2.2, value, fontsize=34, weight="bold", color=INK)
        ax.text(x + 0.3, 1.0, note, fontsize=12, color=MUTED)
    save(fig, "02_headline_metrics.png")


def loao_chart() -> None:
    held = [c for c in CLASSES if (OUTPUTS_DIR / f"loao_{c}.json").exists()]
    if not held:
        return
    d = {c: json.loads((OUTPUTS_DIR / f"loao_{c}.json").read_text()) for c in held}
    series = [("A1 detects", "a1_detect_rate", S1), ("Fused detects", "fused_detect_rate", S2),
              ("A2 flags", "a2_flag_rate", S3)]
    fig, ax = plt.subplots(figsize=SIZE)
    y = np.arange(len(held))[::-1]
    bh = 0.24
    for i, (name, key, color) in enumerate(series):
        vals = [d[c][key] for c in held]
        bars = ax.barh(y + (1 - i) * (bh + 0.03), vals, height=bh, color=color, label=name)
        for b, v in zip(bars, vals):
            ax.text(b.get_width() + 0.01, b.get_y() + bh / 2, f"{v:.1%}" if v >= 0.001 else f"{v:.2%}",
                    va="center", fontsize=12, color=INK)
    ax.set_yticks(y, held, fontsize=14)
    ax.set_xlim(0, 1.08)
    ax.xaxis.set_major_formatter(matplotlib.ticker.PercentFormatter(1.0))
    ax.grid(axis="y", visible=False)
    ax.set_title("Leave-one-attack-out: share of an unseen attack class caught", pad=36)
    ax.text(0, 1.02, "A1 retrained without the held-out class; evaluated on that class's eval flows",
            transform=ax.transAxes, fontsize=12.5, color=INK2)
    ax.legend(loc="lower right", frameon=False, fontsize=13)
    save(fig, "03_loao_detection.png")


def status_by_class(m: dict) -> None:
    statuses = sorted(m["status_counts"], key=lambda s: -m["status_counts"][s])[:3]
    rows = m["status_by_class"]
    classes = [c for c in CLASSES if c in rows]
    share = np.array([[rows[c].get(s, 0) for s in statuses] for c in classes], dtype=float)
    share /= share.sum(1, keepdims=True)
    fig, ax = plt.subplots(figsize=SIZE)
    y = np.arange(len(classes))[::-1]
    left = np.zeros(len(classes))
    for i, s in enumerate(statuses):
        ax.barh(y, share[:, i], left=left, height=0.55, color=SERIES[i][0], label=s,
                edgecolor=SURFACE, linewidth=2)
        for yi, l, v in zip(y, left, share[:, i]):
            if v >= 0.08:
                ax.text(l + v / 2, yi, f"{v:.0%}", ha="center", va="center", fontsize=12.5, color="white")
        left += share[:, i]
    ax.set_yticks(y, classes, fontsize=14)
    ax.xaxis.set_major_formatter(matplotlib.ticker.PercentFormatter(1.0))
    ax.set_xlim(0, 1)
    ax.grid(axis="y", visible=False)
    ax.set_title("How the agents agreed, per true class", pad=36)
    ax.text(0, 1.02, "Share of eval flows by fusion status", transform=ax.transAxes, fontsize=12.5, color=INK2)
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.07), ncol=len(statuses), frameon=False, fontsize=13)
    save(fig, "04_status_by_class.png")


def a2_scores() -> None:
    r = pd.read_parquet(EVAL_RESULTS, columns=[LABEL_COL, "a2_score", "a2_anomalous"])
    thr = r.loc[r["a2_anomalous"], "a2_score"].min() if r["a2_anomalous"].any() else None
    fig, ax = plt.subplots(figsize=SIZE)
    bins = np.linspace(r["a2_score"].min(), r["a2_score"].max(), 80)
    for name, mask, color in (("BENIGN", r[LABEL_COL] == BENIGN, S1), ("Attack", r[LABEL_COL] != BENIGN, S2)):
        ax.hist(r.loc[mask, "a2_score"], bins=bins, density=True, histtype="step", lw=2.5, color=color, label=name)
    if thr is not None:
        ax.axvline(thr, color=INK2, lw=1.5, ls="--")
        ax.text(thr, ax.get_ylim()[1] * 0.95, "  97th pct threshold", color=INK2, fontsize=12, va="top")
    ax.set_xlabel("A2 anomaly score")
    ax.set_ylabel("density")
    ax.set_title("A2 anomaly score: BENIGN vs attack (eval)", pad=36)
    ax.text(0, 1.02, f'ROC-AUC {json.loads(METRICS.read_text())["a2"]["roc_auc_attack_vs_benign"]:.3f}; '
            "few attacks clear the strict threshold", transform=ax.transAxes, fontsize=12.5, color=INK2)
    ax.legend(frameon=False, fontsize=13)
    save(fig, "05_a2_score_distribution.png")


def main() -> None:
    PPT_DIR.mkdir(parents=True, exist_ok=True)
    mpl_style()
    m = json.loads(METRICS.read_text())
    architecture()
    headline(m)
    loao_chart()
    status_by_class(m)
    a2_scores()
    for src, name in ((CONFUSION_A1_PNG, "06_confusion_a1.png"), (CONFUSION_FUSED_PNG, "07_confusion_fused.png")):
        if src.exists():
            shutil.copy(src, PPT_DIR / name)
            print(f"  {name}")
    print(f"-> {PPT_DIR}")


if __name__ == "__main__":
    main()
