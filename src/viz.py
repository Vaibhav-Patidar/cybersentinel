"""Shared chart palette + small inline-SVG chart builders (dashboard) and matplotlib style (PPT)."""
from html import escape

# validated categorical slots (light, dark): blue, orange, aqua
SERIES = [("#2a78d6", "#3987e5"), ("#eb6834", "#d95926"), ("#1baf7a", "#199e70")]
SEQ_BLUE = ["#cde2fb", "#9ec5f4", "#6da7ec", "#3987e5", "#256abf", "#184f95", "#0d366b"]
INK, INK2, MUTED, GRID, BASE, SURFACE = "#0b0b0b", "#52514e", "#898781", "#e1e0d9", "#c3c2b7", "#fcfcfb"


def fmt_pct(v: float) -> str:
    return f"{v:.1%}" if v >= 0.001 or v == 0 else f"{v:.2%}"


def grouped_hbar(categories: list[str], series: dict[str, list[float]], fmt=fmt_pct,
                 vmax: float = 1.0, width: int = 460) -> str:
    """Horizontal grouped bars, value labels on every bar, <title> tooltips. Colors via CSS vars."""
    names = list(series)
    bar_h, gap, group_gap, left, right = 16, 2, 16, 104, 56
    group_h = len(names) * (bar_h + gap) - gap
    height = len(categories) * (group_h + group_gap) + 10
    plot_w = width - left - right
    out = [f'<svg viewBox="0 0 {width} {height}" class="chart" role="img">']
    y = 5
    for ci, cat in enumerate(categories):
        out.append(f'<text x="{left - 10}" y="{y + group_h / 2 + 4}" text-anchor="end" class="lbl">{escape(cat)}</text>')
        for si, name in enumerate(names):
            v = series[name][ci]
            w = max(plot_w * v / vmax, 0)
            by = y + si * (bar_h + gap)
            out.append(
                f'<g><title>{escape(cat)} · {escape(name)}: {fmt(v)}</title>'
                f'<rect x="{left}" y="{by - 1}" width="{plot_w}" height="{bar_h + 2}" fill="transparent"/>'
                f'<rect x="{left}" y="{by}" width="{w:.1f}" height="{bar_h}" rx="3" fill="var(--s{si + 1})"/>'
                f'<text x="{left + w + 6:.1f}" y="{by + bar_h - 3}" class="val">{fmt(v)}</text></g>')
        y += group_h + group_gap
    out.append(f'<line x1="{left}" x2="{left}" y1="0" y2="{height - 5}" class="axis"/></svg>')
    return "".join(out)


def legend(names: list[str]) -> str:
    return '<div class="legend">' + "".join(
        f'<span><i style="background:var(--s{i + 1})"></i>{escape(n)}</span>' for i, n in enumerate(names)) + "</div>"


def heat_table(labels: list[str], matrix: list[list[int]]) -> str:
    """Confusion matrix as an HTML table; cell shade = row-normalised share (sequential blue)."""
    rows = ['<table class="heat"><tr><th>true \\ pred</th>' + "".join(f"<th>{escape(l)}</th>" for l in labels) + "</tr>"]
    for lab, row in zip(labels, matrix):
        total = max(sum(row), 1)
        cells = []
        for v in row:
            share = v / total
            step = min(int(share * (len(SEQ_BLUE) - 1) + 0.999), len(SEQ_BLUE) - 1) if v else -1
            bg = SEQ_BLUE[step] if step >= 0 else "transparent"
            ink = "#ffffff" if step >= 3 else "var(--ink)"
            cells.append(f'<td style="background:{bg};color:{ink}" title="{lab}: {v:,} ({share:.2%})">{v:,}</td>')
        rows.append(f"<tr><th>{escape(lab)}</th>{''.join(cells)}</tr>")
    return "".join(rows) + "</table>"


def mpl_style() -> None:
    """Matplotlib defaults matching the palette (PPT assets)."""
    import matplotlib as mpl
    mpl.rcParams.update({
        "figure.facecolor": SURFACE, "axes.facecolor": SURFACE, "savefig.facecolor": SURFACE,
        "axes.edgecolor": BASE, "axes.labelcolor": INK2, "text.color": INK,
        "xtick.color": MUTED, "ytick.color": INK2, "axes.grid": True, "grid.color": GRID,
        "grid.linewidth": 0.8, "axes.spines.top": False, "axes.spines.right": False,
        "font.size": 12, "axes.titlesize": 15, "axes.titleweight": "bold", "axes.titlelocation": "left",
    })
