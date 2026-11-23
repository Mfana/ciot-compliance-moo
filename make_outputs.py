"""Generate every number, table and figure for the manuscript from results/*.jsonl.

  python3 make_outputs.py        -> outputs/tables/*.csv, outputs/figures/*.png, outputs/numbers.json
"""
import os, json, sys, warnings
import numpy as np, pandas as pd
from scipy import stats
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
warnings.filterwarnings("ignore")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cmof.model import P, CTRL, DOMAINS

ROOT = os.path.dirname(os.path.abspath(__file__))
RES, OUT = os.path.join(ROOT, "results"), os.path.join(ROOT, "outputs")
TAB, FIG = os.path.join(OUT, "tables"), os.path.join(OUT, "figures")
for d in (TAB, FIG):
    os.makedirs(d, exist_ok=True)
OBJ = ["S", "P", "T", "CS"]
OBJ_NAME = {"S": "Security", "P": "Privacy", "T": "Trust (proxy)", "CS": "Compliance coverage"}
COMP = ["C", "I", "A", "CP", "SP", "TP", "TD", "TN", "TCB", "GDPR", "POPIA", "NIST"]
BL = ["B1_checklist", "B2_greedy_security", "B3_compliance_only", "B4_random", "B5_weighted_sum"]
BL_NAME = {"B0_as_is": "As-is (B0)", "B1_checklist": "ETSI checklist (B1)", "B2_greedy_security": "Greedy security (B2)",
           "B3_compliance_only": "Compliance-only (B3)", "B4_random": "Random (B4)", "B5_weighted_sum": "Weighted sum (B5)",
           "knee": "NSGA-II knee"}
DOM_NAME = {"smart_home": "Smart home", "healthcare": "Healthcare", "wearable": "Wearable", "vehicle": "Vehicle",
            "industrial": "Industrial IoT"}
ARM_NAME = {"real": "Real-data arm", "simulated": "Simulated arm"}
RNG = np.random.default_rng(20261123)
NUM = {}
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 9, "axes.spines.top": False, "axes.spines.right": False,
                     "savefig.dpi": 300, "savefig.bbox": "tight"})
C_ARM = {"real": "#1f5f8b", "simulated": "#c4651c"}


def load(name):
    p = os.path.join(RES, f"{name}.jsonl")
    return [json.loads(l) for l in open(p)] if os.path.exists(p) else []


def boot_ci(x, n=10000):
    x = np.asarray(x, float); x = x[~np.isnan(x)]
    if len(x) == 0:
        return (np.nan, np.nan)
    m = x[RNG.integers(len(x), size=(n, len(x)))].mean(1)
    return tuple(np.percentile(m, [2.5, 97.5]))


def rank_biserial(d):
    d = np.asarray(d, float); d = d[np.abs(d) > 1e-12]
    if len(d) == 0:
        return 0.0
    r = stats.rankdata(np.abs(d))
    return float((r[d > 0].sum() - r[d < 0].sum()) / r.sum())


def holm(p):
    p = np.asarray(p, float); o = np.argsort(p); m = len(p); adj = np.empty(m); run = 0
    for rank, i in enumerate(o):
        run = max(run, (m - rank) * p[i]); adj[i] = min(1.0, run)
    return adj


def f3(x):
    return f"{x:.3f}"


# ============================================================================================ E1 main
def e1(recs):
    rows, comp_rows, dom_rows, adopt = [], [], [], []
    for arm in ("real", "simulated"):
        R = [r for r in recs if r["arm"] == arm and "knee" in r]
        NUM[f"E1_{arm}_R"] = len(R)
        NUM[f"E1_{arm}_seconds_median"] = float(np.median([r["seconds"] for r in R]))
        sols = {"B0_as_is": [r["as_is"] for r in R], "knee": [r["knee"] for r in R]}
        for b in BL:
            sols[b] = [r["baselines"][b] for r in R]
        # descriptive table
        for name, S in sols.items():
            row = dict(arm=ARM_NAME[arm], solution=BL_NAME[name])
            for k in OBJ + COMP + ["cost"]:
                v = np.array([s.get(k, np.nan) if s is not None else np.nan for s in S], float)
                lo, hi = boot_ci(v)
                row[k] = np.nanmean(v); row[k + "_lo"] = lo; row[k + "_hi"] = hi; row[k + "_sd"] = np.nanstd(v, ddof=1)
            if name == "B4_random":
                row["meets_cs"] = np.mean([s["meets_cs_share"] for s in S])
            else:
                row["meets_cs"] = np.mean([s["meets_cs"] for s in S])
            row["dominated_by_front"] = (np.mean([s.get("dominated_by_front", False) for s in S]) if name in BL else np.nan)
            rows.append(row)
        # gains over as-is (descriptive)
        for k in OBJ + COMP:
            a = np.array([r["as_is"][k] for r in R]); kn = np.array([r["knee"][k] for r in R])
            NUM[f"E1_{arm}_asis_{k}"] = float(a.mean()); NUM[f"E1_{arm}_knee_{k}"] = float(kn.mean())
            NUM[f"E1_{arm}_gainpct_{k}"] = float(100 * (kn.mean() - a.mean()) / a.mean())
        # paired comparisons knee vs baselines
        for b in BL:
            ps, part = [], []
            for k in OBJ:
                d = np.array([r["knee"][k] - r["baselines"][b][k] for r in R])
                p = stats.wilcoxon(d, zero_method="wilcox").pvalue if np.any(np.abs(d) > 1e-12) else 1.0
                lo, hi = boot_ci(d)
                part.append(dict(arm=ARM_NAME[arm], baseline=BL_NAME[b], objective=OBJ_NAME[k], key=k, mean_diff=d.mean(),
                                 ci_lo=lo, ci_hi=hi, p_raw=p, r_rb=rank_biserial(d), knee_better_share=float(np.mean(d > 1e-12))))
                ps.append(p)
            adj = holm(ps)
            for row, pa in zip(part, adj):
                row["p_holm"] = pa
                row["direction"] = ("knee higher" if row["mean_diff"] > 0 else "knee lower") if pa < 0.05 else "no difference"
            better = any(r_["direction"] == "knee higher" for r_ in part); worse = any(r_["direction"] == "knee lower" for r_ in part)
            verdict = "outperforms" if better and not worse else ("trade-off" if better and worse else
                      ("underperforms" if worse else "no difference"))
            for row in part:
                row["verdict"] = verdict
            comp_rows += part
            NUM[f"E1_{arm}_verdict_{b}"] = verdict
        # per-domain (knee and as-is)
        for dm in DOMAINS:
            for k in OBJ:
                a = np.array([r["as_is"]["by_domain"][dm][k] for r in R], float)
                kn = np.array([r["knee"]["by_domain"][dm][k] for r in R], float)
                lo, hi = boot_ci(kn)
                dom_rows.append(dict(arm=ARM_NAME[arm], domain=DOM_NAME[dm], objective=OBJ_NAME[k], as_is=np.nanmean(a),
                                     knee=np.nanmean(kn), knee_lo=lo, knee_hi=hi, gain=np.nanmean(kn - a)))
            ad = np.array([r["knee"]["adoption"][dm] for r in R]); a0 = np.array([r["as_is"]["adoption"][dm] for r in R])
            for j, k in enumerate(CTRL):
                adopt.append(dict(arm=arm, domain=dm, control=k, as_is=a0[:, j].mean(), knee=ad[:, j].mean()))
        # exact gaps, HV
        gaps = np.array([[(g["value"] - g["best_front"]) / g["value"] for g in r["exact_gap"]] for r in R])
        NUM[f"E1_{arm}_gap_median_pct"] = float(100 * np.median(gaps)); NUM[f"E1_{arm}_gap_max_pct"] = float(100 * gaps.max())
        NUM[f"E1_{arm}_gap_equal_median_pct"] = float(100 * np.median(gaps[:, -1]))
        NUM[f"E1_{arm}_gap_p90_pct"] = float(100 * np.percentile(gaps, 90))
        NUM[f"E1_{arm}_hv_mean"] = float(np.mean([r["nsga2"]["hv"] for r in R]))
        NUM[f"E1_{arm}_front_size_median"] = float(np.median([r["nsga2"]["front_size"] for r in R]))
        NUM[f"E1_{arm}_V_mean"] = float(np.mean([r["V"] for r in R]))
        # adequacy of R
        hw = {k: (boot_ci([r["knee"][k] for r in R])[1] - boot_ci([r["knee"][k] for r in R])[0]) / 2 for k in OBJ}
        NUM[f"E1_{arm}_ci_halfwidth_max"] = float(max(hw.values()))
    # real vs simulated: knee gain over as-is
    arm_rows = []
    for k in OBJ + COMP:
        g = {arm: np.array([r["knee"][k] - r["as_is"][k] for r in recs if r["arm"] == arm and "knee" in r]) for arm in ("real", "simulated")}
        u = stats.mannwhitneyu(g["real"], g["simulated"], alternative="two-sided")
        arm_rows.append(dict(component=k, gain_real=g["real"].mean(), gain_sim=g["simulated"].mean(), p=u.pvalue))
    ar = pd.DataFrame(arm_rows); ar["p_holm"] = holm(ar.p.values)
    ar.to_csv(os.path.join(TAB, "E1_real_vs_simulated_gain.csv"), index=False)
    ad = pd.DataFrame(adopt); ad.to_csv(os.path.join(TAB, "E1_control_adoption.csv"), index=False)
    desc = pd.DataFrame(rows); desc.to_csv(os.path.join(TAB, "E1_descriptive.csv"), index=False)
    cmp_ = pd.DataFrame(comp_rows); cmp_.to_csv(os.path.join(TAB, "E1_comparisons.csv"), index=False)
    dom = pd.DataFrame(dom_rows); dom.to_csv(os.path.join(TAB, "E1_by_domain.csv"), index=False)
    return desc, cmp_, dom, ad, ar


def fig_distributions(recs):
    fig, axes = plt.subplots(1, 4, figsize=(9.5, 2.9))
    for ax, k in zip(axes, OBJ):
        data, pos, cols = [], [], []
        for j, arm in enumerate(("real", "simulated")):
            R = [r for r in recs if r["arm"] == arm and "knee" in r]
            for m, key in enumerate(("as_is", "B1", "knee")):
                v = [r["as_is"][k] if key == "as_is" else (r["baselines"]["B1_checklist"][k] if key == "B1" else r["knee"][k]) for r in R]
                data.append(v); pos.append(j * 3.6 + m); cols.append(C_ARM[arm])
        bp = ax.boxplot(data, positions=pos, widths=0.7, patch_artist=True, showfliers=False, medianprops=dict(color="black"))
        for patch, c, m in zip(bp["boxes"], cols, [0, 1, 2] * 2):
            patch.set_facecolor(c); patch.set_alpha([0.25, 0.55, 0.9][m])
        ax.set_xticks(pos); ax.set_xticklabels(["As-is", "ETSI", "Knee"] * 2, rotation=90, fontsize=7)
        ax.set_title(OBJ_NAME[k], fontsize=9)
        ax.text(1, -0.42, "Real", transform=ax.get_xaxis_transform(), ha="center", fontsize=7, color=C_ARM["real"])
        ax.text(4.6, -0.42, "Simulated", transform=ax.get_xaxis_transform(), ha="center", fontsize=7, color=C_ARM["simulated"])
    axes[0].set_ylabel("Fleet score (0-1)")
    fig.tight_layout(); fig.savefig(os.path.join(FIG, "fig3_distributions.png")); plt.close(fig)


def fig_front(recs):
    r = next(r for r in recs if r["arm"] == "real" and r.get("front_objs"))
    F = np.array(r["front_objs"])
    fig, axes = plt.subplots(1, 3, figsize=(9.5, 3.0))
    mk = {"B1_checklist": ("s", "ETSI checklist"), "B2_greedy_security": ("^", "Greedy security"),
          "B3_compliance_only": ("D", "Compliance-only"), "B4_random": ("x", "Random (mean)"), "B5_weighted_sum": ("P", "Weighted sum")}
    for ax, k in zip(axes, ["S", "P", "T"]):
        sc = ax.scatter(F[:, 3], F[:, OBJ.index(k)], c="#1f5f8b", s=10, alpha=0.6, label="NSGA-II front")
        for b, (m, lab) in mk.items():
            v = r["baselines"][b]
            if v is not None:
                ax.scatter(v["CS"], v[k], marker=m, s=40, edgecolor="black", facecolor="white" if m != "x" else "black", label=lab, zorder=3)
        ax.scatter(r["knee"]["CS"], r["knee"][k], marker="*", s=140, color="#c4651c", edgecolor="black", label="Knee", zorder=4)
        ax.scatter(r["as_is"]["CS"], r["as_is"][k], marker="o", s=30, color="grey", label="As-is", zorder=3)
        ax.set_xlabel("Compliance coverage"); ax.set_ylabel(OBJ_NAME[k])
    axes[0].legend(fontsize=6.5, frameon=False, loc="lower right")
    fig.suptitle(f"Real-data arm, replication {r['rep']}, budget fraction {r['budget_frac']}: four-objective front projected on compliance",
                 fontsize=8.5)
    fig.tight_layout(); fig.savefig(os.path.join(FIG, "fig4_front.png")); plt.close(fig)


def fig_domain(dom, ad):
    fig, axes = plt.subplots(1, 2, figsize=(9.5, 3.2), gridspec_kw=dict(width_ratios=[1, 1.6]))
    d = dom[dom.arm == ARM_NAME["real"]].pivot(index="domain", columns="objective", values="knee")
    d0 = dom[dom.arm == ARM_NAME["real"]].pivot(index="domain", columns="objective", values="as_is")
    d = d.loc[[DOM_NAME[x] for x in DOMAINS], [OBJ_NAME[k] for k in OBJ]]; d0 = d0.loc[d.index, d.columns]
    im = axes[0].imshow(d.values, cmap="Blues", vmin=0, vmax=1, aspect="auto")
    for (i, j), v in np.ndenumerate(d.values):
        axes[0].text(j, i, f"{d0.values[i, j]:.2f}→{v:.2f}", ha="center", va="center", fontsize=6.5, color="white" if v > 0.6 else "black")
    axes[0].set_xticks(range(4)); axes[0].set_xticklabels(["S", "P", "T", "CS"]); axes[0].set_yticks(range(5)); axes[0].set_yticklabels(d.index)
    axes[0].set_title("Real-data arm: as-is → knee by domain", fontsize=8.5)
    a = ad[ad.arm == "real"].pivot(index="domain", columns="control", values="knee").loc[DOMAINS, CTRL]
    im2 = axes[1].imshow(a.values, cmap="Oranges", vmin=0, vmax=1, aspect="auto")
    for (i, j), v in np.ndenumerate(a.values):
        axes[1].text(j, i, f"{v:.2f}", ha="center", va="center", fontsize=6, color="white" if v > 0.6 else "black")
    axes[1].set_xticks(range(len(CTRL))); axes[1].set_xticklabels(CTRL, fontsize=7); axes[1].set_yticks(range(5))
    axes[1].set_yticklabels([DOM_NAME[x] for x in DOMAINS]); axes[1].set_title("Share of devices with each control at the knee", fontsize=8.5)
    fig.tight_layout(); fig.savefig(os.path.join(FIG, "fig5_domains.png")); plt.close(fig)


# ============================================================================================ E2 sweep
def e2(recs):
    rows = []
    for arm in ("real", "simulated"):
        for b in sorted({r["budget_frac"] for r in recs}):
            R = [r for r in recs if r["arm"] == arm and r["budget_frac"] == b]
            for k in OBJ:
                kn = np.array([r["knee"][k] if "knee" in r else np.nan for r in R])
                rows.append(dict(arm=arm, budget=b, objective=k, knee_median=np.nanmedian(kn), q1=np.nanpercentile(kn, 25),
                                 q3=np.nanpercentile(kn, 75), as_is=np.mean([r["as_is"][k] for r in R]),
                                 feasible_share=np.mean(["knee" in r for r in R])))
            gaps = [100 * (g["value"] - g["best_front"]) / g["value"] for r in R for g in r["exact_gap"]
                    if g["value"] is not None and g["best_front"] is not None]
            NUM[f"E2_{arm}_b{b}_gap_median_pct"] = float(np.median(gaps)) if gaps else None
            NUM[f"E2_{arm}_b{b}_feasible_share"] = float(np.mean(["knee" in r for r in R]))
    df = pd.DataFrame(rows); df.to_csv(os.path.join(TAB, "E2_budget_sweep.csv"), index=False)
    fig, axes = plt.subplots(1, 4, figsize=(9.5, 2.6), sharex=True)
    for ax, k in zip(axes, OBJ):
        for arm in ("real", "simulated"):
            d = df[(df.arm == arm) & (df.objective == k)]
            ax.plot(d.budget, d.knee_median, "-o", color=C_ARM[arm], ms=3, label=ARM_NAME[arm])
            ax.fill_between(d.budget, d.q1, d.q3, color=C_ARM[arm], alpha=0.2)
            ax.axhline(d.as_is.mean(), color=C_ARM[arm], ls=":", lw=0.8)
        if k == "CS":
            ax.axhline(P["constraints"]["compliance_threshold"], color="black", ls="--", lw=0.7)
        ax.set_title(OBJ_NAME[k], fontsize=9); ax.set_xlabel("Budget fraction")
    axes[0].set_ylabel("Knee score (median, IQR)"); axes[0].legend(fontsize=7, frameon=False)
    fig.tight_layout(); fig.savefig(os.path.join(FIG, "fig6_budget.png")); plt.close(fig)
    return df


# ============================================================================================ E3 algorithms
def e3(recs):
    rows = []
    for a in ("NSGA2", "NSGA3", "MOEAD", "NSGA2_bitstring"):
        g = np.array([[x for x in r[a]["gaps"] if x is not None] for r in recs], dtype=object)
        allg = np.concatenate([np.array(x, float) for x in g]) * 100
        rows.append(dict(algorithm=a, hv_mean=np.mean([r[a]["hv"] for r in recs]), hv_sd=np.std([r[a]["hv"] for r in recs], ddof=1),
                         gap_median_pct=np.median(allg), gap_p90_pct=np.percentile(allg, 90), gap_max_pct=allg.max(),
                         front_size=np.median([r[a]["front_size"] for r in recs]), seconds=np.median([r[a]["seconds"] for r in recs])))
    df = pd.DataFrame(rows)
    base = np.array([r["NSGA2"]["hv"] for r in recs])
    df["hv_vs_nsga2_p"] = [np.nan] + [stats.wilcoxon(np.array([r[a]["hv"] for r in recs]) - base).pvalue
                                      for a in ("NSGA3", "MOEAD", "NSGA2_bitstring")]
    df.to_csv(os.path.join(TAB, "E3_algorithms.csv"), index=False)
    for _, r in df.iterrows():
        NUM[f"E3_{r.algorithm}_gap_median_pct"] = float(r.gap_median_pct); NUM[f"E3_{r.algorithm}_hv"] = float(r.hv_mean)
        NUM[f"E3_{r.algorithm}_seconds"] = float(r.seconds)
    return df


# ============================================================================================ E4/E5 robustness
def robustness(recs, main, name):
    ref = {r["rep"]: r for r in main if r["arm"] == "real" and r["rep"] < 20 and "knee" in r}
    rows = []
    for s in sorted({r["setting"] for r in recs}):
        R = [r for r in recs if r["setting"] == s and "knee" in r]
        row = dict(setting=s, n=len(R))
        for k in OBJ:
            row[f"{k}_knee"] = np.mean([r["knee"][k] for r in R])
            row[f"{k}_delta_vs_ref"] = np.mean([r["knee"][k] - ref[r["rep"]]["knee"][k] for r in R if r["rep"] in ref])
            row[f"{k}_gain"] = np.mean([r["knee"][k] - r["as_is"][k] for r in R])
        for b in ("B1_checklist", "B2_greedy_security", "B5_weighted_sum"):
            verdict = []
            for k in OBJ:
                d = np.array([r["knee"][k] - r["baselines"][b][k] for r in R])
                p = stats.wilcoxon(d).pvalue if np.any(np.abs(d) > 1e-12) else 1.0
                verdict.append((k, d.mean(), p))
            adj = holm([v[2] for v in verdict])
            dirs = ["+" if (pa < 0.05 and v[1] > 0) else ("-" if pa < 0.05 else "0") for v, pa in zip(verdict, adj)]
            row[f"vs_{b}"] = "".join(dirs)
        row["meets_cs_share"] = np.mean([r["knee"]["meets_cs"] for r in R])
        row["gap_median_pct"] = float(np.median([100 * (g["value"] - g["best_front"]) / g["value"] for r in R for g in r["exact_gap"]
                                                 if g["value"] and g["best_front"] is not None]))
        rows.append(row)
    # reference row (E1 real arm, reps 0-19) for the same summaries
    R = list(ref.values()); row = dict(setting="REFERENCE (E1 reps 0-19)", n=len(R))
    for k in OBJ:
        row[f"{k}_knee"] = np.mean([r["knee"][k] for r in R]); row[f"{k}_delta_vs_ref"] = 0.0
        row[f"{k}_gain"] = np.mean([r["knee"][k] - r["as_is"][k] for r in R])
    for b in ("B1_checklist", "B2_greedy_security", "B5_weighted_sum"):
        verdict = []
        for k in OBJ:
            d = np.array([r["knee"][k] - r["baselines"][b][k] for r in R]); verdict.append((k, d.mean(), stats.wilcoxon(d).pvalue))
        adj = holm([v[2] for v in verdict])
        row[f"vs_{b}"] = "".join(["+" if (pa < 0.05 and v[1] > 0) else ("-" if pa < 0.05 else "0") for v, pa in zip(verdict, adj)])
    row["meets_cs_share"] = np.mean([r["knee"]["meets_cs"] for r in R])
    rows.insert(0, row)
    df = pd.DataFrame(rows); df.to_csv(os.path.join(TAB, f"{name}.csv"), index=False)
    return df


LABEL = {"beta=0.05": "Exploit propensity 0.05", "beta=0.2": "Exploit propensity 0.20", "cost_jitter_0": "Costs perturbed (draw 1)",
         "cost_jitter_1": "Costs perturbed (draw 2)", "cost_jitter_2": "Costs perturbed (draw 3)", "effect_x0.7": "Control effect x0.7",
         "effect_x1.3": "Control effect x1.3", "lambda=10": "10 vulnerabilities/device", "lambda=2": "2 vulnerabilities/device",
         "latency_caps_x0.5": "Latency caps x0.5", "latency_caps_x1.5": "Latency caps x1.5", "prevalence=0.1": "Existing controls 0.1",
         "prevalence=0.5": "Existing controls 0.5", "rho=0.25": "IDS response 0.25", "rho=0.75": "IDS response 0.75",
         "chipset_excluded": "Chipset CVEs excluded", "cve_synthetic": "Simulated CVE records", "ids_synthetic": "Simulated IDS rates",
         "kev_off": "No KEV multiplier", "tp_synthetic": "Simulated transfer protection"}


def fig_robust(e4, e5):
    from matplotlib.ticker import MaxNLocator
    from matplotlib.patches import Patch
    df = pd.concat([e4.assign(kind="Sensitivity"), e5.assign(kind="Ablation")])
    df = df[df.setting != "REFERENCE (E1 reps 0-19)"]
    fig, axes = plt.subplots(1, 4, figsize=(9.5, 4.6), sharey=True)
    y = np.arange(len(df))
    for ax, k in zip(axes, OBJ):
        ax.barh(y, df[f"{k}_delta_vs_ref"], color=["#1f5f8b" if t == "Sensitivity" else "#c4651c" for t in df.kind])
        ax.axvline(0, color="black", lw=0.6); ax.set_title(OBJ_NAME[k], fontsize=9); ax.set_xlabel("\u0394 knee vs reference", fontsize=8)
        ax.xaxis.set_major_locator(MaxNLocator(3, symmetric=True)); ax.tick_params(axis="x", labelsize=7)
    axes[0].set_yticks(y); axes[0].set_yticklabels([LABEL.get(s, s) for s in df.setting], fontsize=7); axes[0].invert_yaxis()
    fig.legend(handles=[Patch(color="#1f5f8b", label="Sensitivity (E4)"), Patch(color="#c4651c", label="Ablation (E5)")],
               loc="upper center", ncol=2, fontsize=8, frameon=False, bbox_to_anchor=(0.6, 1.02))
    fig.tight_layout(rect=(0, 0, 1, 0.95)); fig.savefig(os.path.join(FIG, "fig7_robustness.png")); plt.close(fig)


if __name__ == "__main__":
    main = load("main")
    if main:
        desc, cmp_, dom, ad, ar = e1(main)
        fig_distributions(main); fig_front(main); fig_domain(dom, ad)
    sw = load("sweep")
    if sw:
        e2(sw)
    al = load("algos")
    if al:
        e3(al)
    e4r, e5r = load("sensitivity"), load("ablation")
    e4 = robustness(e4r, main, "E4_sensitivity") if e4r else None
    e5 = robustness(e5r, main, "E5_ablation") if e5r else None
    if e4 is not None and e5 is not None:
        fig_robust(e4, e5)
    json.dump(NUM, open(os.path.join(OUT, "numbers.json"), "w"), indent=1, default=float)
    print(json.dumps({k: (round(v, 4) if isinstance(v, float) else v) for k, v in NUM.items()}, indent=0)[:6000])
