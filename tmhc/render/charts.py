"""Small pictures drawn from the exports (no screenshots needed)."""
from __future__ import annotations

import io
from typing import Optional


def computer_status_png(metrics: dict) -> Optional[bytes]:
    """'Computer Status' widget look-alike: pie + legend with counts, dark theme."""
    total = metrics.get("deployed_agents")
    if not total:
        return None
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    items = [("Critical", metrics.get("critical", 0), "#f0524f"),
             ("Warning", metrics.get("warning", 0), "#ff7633"),
             ("Managed", metrics.get("managed", 0), "#04c55b"),
             ("Unmanaged", metrics.get("unmanaged", 0), "#8a8a8a")]
    bg = "#1e1e1e"
    fig = plt.figure(figsize=(3.72, 3.0), dpi=150, facecolor=bg)
    ax = fig.add_axes([0.02, 0.06, 0.52, 0.72])
    vals = [v for _, v, _ in items if v]
    cols = [c for _, v, c in items if v]
    ax.pie(vals, colors=cols, startangle=90, counterclock=False,
           wedgeprops={"linewidth": 0.6, "edgecolor": bg})
    ax.set_aspect("equal")
    fig.text(0.04, 0.9, "Computer Status", color="#e6e6e6", fontsize=9, fontweight="bold")
    fig.text(0.57, 0.66, "COMPUTER STATUS", color="#d0d0d0", fontsize=6.5, fontweight="bold")
    y = 0.57
    for label, v, c in items:
        fig.patches.append(matplotlib.patches.Circle((0.6, y + 0.012), 0.016, transform=fig.transFigure,
                                                     color=c, figure=fig))
        fig.text(0.64, y, label, color="#d8d8d8", fontsize=7)
        fig.text(0.93, y, str(v), color="#5b9bd5", fontsize=7, ha="right")
        y -= 0.085
    buf = io.BytesIO()
    fig.savefig(buf, format="png", facecolor=bg)
    plt.close(fig)
    return buf.getvalue()


# --------------------------------------------------------------------------
# Dark charts in the analysts' Excel style (CECP detections)
# --------------------------------------------------------------------------
_BAR = "#1f6a96"
_TXT = "#d9d9d9"


def _dark_figure(title: str, w: float = 5.0, h: float = 3.0):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np

    from matplotlib import font_manager
    have = {f.name for f in font_manager.fontManager.ttflist}
    # Thai / CJK sender names fall back to an installed font with those glyphs
    plt.rcParams["font.family"] = [f for f in ("DejaVu Sans", "Loma", "Garuda", "Noto Sans Thai",
                                               "Noto Sans CJK JP") if f in have] or ["DejaVu Sans"]
    fig = plt.figure(figsize=(w, h), dpi=150)
    bg = fig.add_axes([0, 0, 1, 1], zorder=-10)
    yy, xx = np.mgrid[-1:1:200j, -1:1:300j]
    r = np.clip(np.sqrt(xx ** 2 + yy ** 2) / 1.3, 0, 1)
    shade = 0.36 - 0.20 * r                     # radial grey: lighter centre, dark edges
    bg.imshow(np.dstack([shade, shade, shade]), aspect="auto", extent=(0, 1, 0, 1))
    bg.axis("off")
    fig.text(0.5, 0.93, title, color="#f2f2f2", fontsize=10.5, fontweight="bold", ha="center", va="center")
    return fig, plt


def _wrap(label: str, width: int = 38) -> str:
    label = str(label)
    return label if len(label) <= width else label[:width - 3] + "..."


def dark_bar_png(title: str, items: list[tuple[str, int]], vertical: bool = False) -> Optional[bytes]:
    """Bar chart (horizontal by default) with value labels, dark gradient background."""
    if not items:
        return None
    import textwrap
    fig, plt = _dark_figure(title)
    labels = [str(k) for k, _ in items]
    vals = [int(v) for _, v in items]
    top = max(vals) or 1
    if vertical:
        ax = fig.add_axes([0.1, 0.24, 0.86, 0.6])
        ax.bar(range(len(vals)), vals, color=_BAR, width=0.55, edgecolor="#2f86b8", linewidth=0.6)
        ax.set_xticks(range(len(vals)))
        ax.set_xticklabels(["\n".join(textwrap.wrap(lb, 70)[:3]) for lb in labels], color=_TXT, fontsize=5.5)
        for i, v in enumerate(vals):
            ax.text(i, v + top * 0.03, str(v), color=_TXT, fontsize=6.5, ha="center")
        ax.set_ylim(0, top * 1.2)
        ax.set_xlim(-0.9, len(vals) - 0.1)
        ax.tick_params(axis="y", colors=_TXT, labelsize=6.5)
        ax.yaxis.grid(True, color="#6b6b6b", linewidth=0.5)
    else:
        n = len(vals)
        ax = fig.add_axes([0.42, 0.12, 0.52, 0.72])
        ys = list(range(n))[::-1]
        ax.barh(ys, vals, color=_BAR, height=0.55 if n > 3 else 0.45, edgecolor="#2f86b8", linewidth=0.6)
        ax.set_yticks(ys)
        ax.set_yticklabels([_wrap(lb) for lb in labels], color=_TXT, fontsize=6.5 if n > 5 else 7)
        for y, v in zip(ys, vals):
            ax.text(v + top * 0.02, y, str(v), color=_TXT, fontsize=6.5, va="center")
        ax.set_xlim(0, top * 1.18)
        ax.tick_params(axis="x", colors=_TXT, labelsize=6.5)
        ax.xaxis.grid(True, color="#6b6b6b", linewidth=0.5)
        if top <= 2:
            ax.set_xticks([x * 0.5 for x in range(int(top * 1.18 / 0.5) + 1)])
        elif top <= 12:
            ax.set_xticks(range(0, int(top * 1.18) + 1, 2 if top > 6 else 1))
    ax.set_facecolor("none")
    ax.set_axisbelow(True)
    for s in ax.spines.values():
        s.set_visible(False)
    ax.tick_params(length=0)
    buf = io.BytesIO()
    fig.savefig(buf, format="png")
    plt.close(fig)
    return buf.getvalue()


def dark_pie_png(title: str, items: list[tuple[str, int]]) -> Optional[bytes]:
    """'Action' pie with an outside label "<name>, <pct>%" in a white box, dark background."""
    if not items:
        return None
    fig, plt = _dark_figure(title)
    ax = fig.add_axes([0.25, 0.06, 0.5, 0.78])
    vals = [int(v) for _, v in items]
    colors = [_BAR, "#ed7d31", "#a5a5a5", "#ffc000", "#5b9bd5", "#70ad47"]
    wedges, _ = ax.pie(vals, colors=colors[:len(vals)], startangle=90, counterclock=False,
                       wedgeprops={"linewidth": 0.8, "edgecolor": "#3a3a3a"})
    total = sum(vals) or 1
    import math
    for wdg, (name, v) in zip(wedges, items):
        ang = (wdg.theta2 + wdg.theta1) / 2 if len(vals) > 1 else -60
        x, y = math.cos(math.radians(ang)), math.sin(math.radians(ang))
        ax.annotate(f"{name}, {round(100 * v / total)}%", xy=(0.95 * x, 0.95 * y), xytext=(1.35 * x + 0.25, 1.15 * y),
                    fontsize=6.5, color="#262626", ha="left", va="center",
                    bbox={"boxstyle": "square,pad=0.35", "fc": "white", "ec": "#bfbfbf", "lw": 0.5},
                    arrowprops={"arrowstyle": "-", "color": "#d9d9d9", "lw": 0.6})
    ax.set_aspect("equal")
    buf = io.BytesIO()
    fig.savefig(buf, format="png")
    plt.close(fig)
    return buf.getvalue()
