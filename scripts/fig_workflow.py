"""Figure 2: operational workflow and decision rules (Reviewer 2)."""
import os, sys
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, Polygon

OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "outputs", "figures")
os.makedirs(OUT, exist_ok=True)
plt.rcParams.update({"font.family": "DejaVu Sans"})
fig, ax = plt.subplots(figsize=(10, 6.6)); ax.set_xlim(0, 100); ax.set_ylim(0, 66); ax.axis("off")
BLUE, ORANGE, GREY, GREEN = "#dbe8f3", "#fbe3cf", "#eeeeee", "#e2f0d9"


def box(x, y, w, h, title, body, fc):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.4,rounding_size=1.2", fc=fc, ec="#333333", lw=0.8))
    ax.text(x + w / 2, y + h - 1.6, title, ha="center", va="top", fontsize=8.2, weight="bold")
    ax.text(x + w / 2, y + h - 4.3, body, ha="center", va="top", fontsize=6.9, linespacing=1.35)


def arrow(x1, y1, x2, y2, text=None, dx=0.0, dy=0.8):
    ax.annotate("", xy=(x2, y2), xytext=(x1, y1), arrowprops=dict(arrowstyle="-|>", lw=0.9, color="#333333"))
    if text:
        ax.text((x1 + x2) / 2 + dx, (y1 + y2) / 2 + dy, text, fontsize=6.6, ha="center", style="italic")


def diamond(cx, cy, w, h, text):
    ax.add_patch(Polygon([(cx, cy + h / 2), (cx + w / 2, cy), (cx, cy - h / 2), (cx - w / 2, cy)], closed=True, fc="white", ec="#333333", lw=0.8))
    ax.text(cx, cy, text, ha="center", va="center", fontsize=6.8, linespacing=1.25)


# row 1: inputs -> state estimation
box(1, 46, 21, 17, "1  Inventory & telemetry", "device list with CPE identifiers\nper-device traffic (flows,\nprotocols, ports)\nlatency / throughput budgets\nsecurity budget B", GREY)
box(27, 46, 22, 17, "2  Vulnerability matching", "CPE → NVD CVE records\nCVSS v3.1 C/I/A impact,\nattack vector, exploitability\nCWE → weakness class\nCISA KEV → exploited flag", BLUE)
box(53.5, 46, 22, 17, "3  Device state", "measured encrypted share\n(transfer protection)\nIDS detection by attack class\nexisting controls (as-is x⁰)\nexploit likelihood pᵥ (Eq. 1)", BLUE)
box(80, 46, 19, 17, "4  Control menu", "12 controls (ETSI EN 303 645,\nNIST IR 8259A, CSF 2.0)\ncost, latency, throughput\nper device; feasible\nconfigurations only", BLUE)
arrow(22.8, 54.5, 26.2, 54.5); arrow(49.8, 54.5, 53.2, 54.5); arrow(75.8, 54.5, 79.2, 54.5)

# row 2: optimisation -> front -> decision
box(66, 22, 33, 17, "5  Multi-objective optimisation", "max  S, P, T, CS   (Eqs. 6, 10, 12, 14)\ns.t. budget, latency, throughput, CS ≥ 0.6\nNSGA-II, device-level encoding\nexact MILP check of weighted optima", ORANGE)
arrow(89.5, 45.2, 89.5, 39.8)
box(33, 22, 27, 17, "6  Pareto front & choice", "trade-off front between\nsecurity, privacy, trust proxies\nand compliance coverage\nknee point as default;\ndecision-maker may re-weight", ORANGE)
arrow(65.2, 30.5, 60.8, 30.5)
diamond(17, 30.5, 22, 13, "Feasible front with\nCS ≥ threshold?")
arrow(32.2, 30.5, 28.2, 30.5)
# "No" path: up from the diamond, right along the free corridor between rows, down into step 5
ax.plot([17, 17, 72], [37.2, 42.3, 42.3], color="#777777", lw=0.8, ls="--")
ax.annotate("", xy=(72, 39.9), xytext=(72, 42.3), arrowprops=dict(arrowstyle="-|>", lw=0.8, color="#777777", ls="--"))
ax.text(42, 43.1, "No → raise B, relax a cap, or offload a control, and re-optimise", fontsize=6.6, ha="center", style="italic", color="#444444")

# row 3: outputs
box(1, 2, 31, 16, "7  Deployment plan", "per-device control set,\ncost, latency and throughput use\nper-domain adoption", GREEN)
box(36, 2, 30, 16, "8  Traceability report", "requirement coverage for GDPR (8),\nPOPIA (7), NIST CSF 2.0 (7) by device;\nunmet requirements listed;\nfor legal review, not a verdict", GREEN)
box(70, 2, 29, 16, "9  Monitor & re-run", "new CVE / KEV entry, firmware\nchange, traffic shift or new device\n→ repeat steps 2-6", GREY)
arrow(17, 23.8, 17, 18.6, "Yes", dx=2.2, dy=0)
arrow(32.6, 10, 35.4, 10); arrow(66.6, 10, 69.4, 10)
# re-run loop: from step 9 out to the right margin, up above row 1, left, down into step 2
ax.plot([99.8, 101.5, 101.5, 38], [10, 10, 65.3, 65.3], color="#777777", lw=0.8, ls="--", clip_on=False)
ax.annotate("", xy=(38, 63.6), xytext=(38, 65.3), arrowprops=dict(arrowstyle="-|>", lw=0.8, color="#777777", ls="--"), annotation_clip=False)
ax.text(70, 66.0, "re-run loop (step 9 \u2192 step 2)", fontsize=6.6, style="italic", color="#444444", ha="center")
fig.savefig(os.path.join(OUT, "fig2_workflow.png"), dpi=300, bbox_inches="tight")
print("ok")
