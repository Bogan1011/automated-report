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
