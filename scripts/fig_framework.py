"""Figure 1 (revised): the compliance-aware multi-objective framework, consistent with Eqs. 1-17."""
import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Rectangle, FancyArrow

OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "outputs", "figures")
plt.rcParams.update({"font.family": "DejaVu Sans"})
fig, ax = plt.subplots(figsize=(10, 7.4)); ax.set_xlim(0, 100); ax.set_ylim(0, 74); ax.axis("off")
GREY, BLUE, DARK, PALE = "#c8c8c8", "#a9cbea", "#1a5f80", "#e6e6e6"


def band(y, text, h=3.6):
    ax.add_patch(Rectangle((0.5, y), 99, h, fc=GREY, ec="#163a52", lw=1.2))
    ax.text(50, y + h / 2, text, ha="center", va="center", fontsize=11.5, weight="bold")


def cell(x, y, w, h, title, body=None, fs=9.5):
    ax.add_patch(Rectangle((x, y), w, h, fc=BLUE, ec="#163a52", lw=1.2))
    if body is None:
        ax.text(x + w / 2, y + h / 2, title, ha="center", va="center", fontsize=fs)
    else:
        ax.text(x + w / 2, y + h - 1.0, title, ha="center", va="top", fontsize=fs, weight="bold")
        ax.text(x + w / 2, y + h - 3.6, body, ha="center", va="top", fontsize=8.2, linespacing=1.35)


def down(y):
    ax.add_patch(FancyArrow(50, y, 0, -2.4, width=2.2, head_width=6.5, head_length=1.6, length_includes_head=True, fc=DARK, ec=DARK))


band(69.5, "CIoT ECOSYSTEM INPUTS")
for j, t in enumerate(["Smart homes", "Healthcare", "Wearables", "Connected vehicles", "Industrial IoT"]):
    cell(0.5 + j * 20, 65.2, 19, 3.4, t)
ax.text(50, 63.2, "device inventory (CPE)  •  NVD / KEV vulnerability records  •  traffic telemetry  •  existing controls",
        ha="center", fontsize=8.2, style="italic")
down(62.3)
band(55.8, "SECURITY, PRIVACY, TRUST AND COMPLIANCE LAYER")
cell(0.5, 44.6, 24, 10.3, "SECURITY (S)", "Confidentiality (C)\nIntegrity (I)\nAvailability (A)")
cell(25.5, 44.6, 24, 10.3, "PRIVACY (P)", "Collection protection (CP)\nStorage protection (SP)\nTransfer protection (TP)")
cell(50.5, 44.6, 24, 10.3, "TRUST PROXIES (T)", "Device (TD)\nNetwork (TN)\nConsumer-facing (TCB)")
cell(75.5, 44.6, 24, 10.3, "COMPLIANCE (CS)", "coverage of GDPR (8),\nPOPIA (7) and NIST CSF 2.0\n(7) requirements")
down(43.7)
band(37.2, "CONTROL CATALOGUE AND TRACEABILITY")
for j, t in enumerate(["12 controls: ETSI EN 303 645,\nNIST IR 8259A, NIST CSF 2.0", "cost, latency and throughput\nper control and domain",
                       "requirement → control rules\n(traceability matrix)"]):
    cell(0.5 + j * 33.2, 31.8, 32.4, 4.6, t, fs=8.6)
down(30.9)
band(24.4, "MULTI-OBJECTIVE OPTIMIZATION ENGINE")
ax.add_patch(Rectangle((14, 10.6), 72, 13.0, fc=PALE, ec="none"))
ax.text(50, 22.6, "Maximize  S, P, T, CS", ha="center", va="top", fontsize=10.5, weight="bold")
ax.text(50, 19.9, "over binary decisions xᵢₖ (control k on device i), keeping existing controls", ha="center", va="top", fontsize=8.6)
ax.text(50, 17.2, "Subject to:  budget B  •  latency L_max per domain  •  throughput Θ_min per domain  •  CS ≥ 0.6",
        ha="center", va="top", fontsize=8.6)
ax.text(50, 14.3, "NSGA-II (device-level encoding)  •  exact MILP check of weighted optima  •  NSGA-III, MOEA/D for comparison",
        ha="center", va="top", fontsize=8.6)
down(9.9)
band(3.4, "DECISION-SUPPORT LAYER")
ax.text(50, 1.4, "Pareto front and knee solution  •  per-device deployment plan  •  requirement traceability report  •  re-run on change",
        ha="center", fontsize=8.6)
fig.savefig(os.path.join(OUT, "fig1_framework.png"), dpi=300, bbox_inches="tight")
print("ok")
