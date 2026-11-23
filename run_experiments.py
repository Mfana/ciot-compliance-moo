"""Run every experiment in PROTOCOL.md. Results go to results/<experiment>.jsonl (one line per replication x setting).

  python3 run_experiments.py main         # E1: both arms, R=50, reference budget
  python3 run_experiments.py sweep        # E2: both arms, R=20, six budget levels
  python3 run_experiments.py algos        # E3: real arm, R=20, NSGA-II vs NSGA-III vs MOEA/D vs bit-string NSGA-II
  python3 run_experiments.py sensitivity  # E4: real arm, R=20, one-at-a-time parameter changes
  python3 run_experiments.py ablation     # E5: real arm, R=20, each real data source replaced by its simulated counterpart
Optional: --reps N (fewer replications, for testing only) --workers W
"""
import sys, os, json, time, argparse, warnings
warnings.filterwarnings("ignore", category=RuntimeWarning)
import numpy as np
from multiprocessing import Pool
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cmof.model import Instance, load_real, P, CTRL, K, DOMAINS
from cmof.opt import (OBJ, CS_TH, DeviceMenus, run_menu_moea, run_moea, knee, hypervolume, exact_weighted,
                      baseline_checklist, baseline_greedy_security, baseline_random, static_ratio)
from pymoo.util.ref_dirs import get_reference_directions

ROOT = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(ROOT, "results")
REAL = None
KEYS = ("C", "I", "A", "S", "CP", "SP", "TP", "P", "TD", "TN", "TCB", "T", "GDPR", "POPIA", "NIST", "CS")
WEIGHTS = [list(w) for w in get_reference_directions("das-dennis", 4, n_partitions=2)] + [[0.25] * 4]


def seed_of(rep, arm, extra=0):
    return P["replications"]["base_seed"] + 1000 * rep + (0 if arm == "real" else 500) + extra


def summarize(inst, X):
    f = inst.fleet(X)
    d = inst.device_scores(X)
    cost, lat, thr = inst.resources(X)
    out = {k: float(f[k]) for k in KEYS}
    out["cost"] = float(cost)
    out["meets_cs"] = bool(f["CS"] >= CS_TH - 1e-9)
    out["by_domain"] = {dm: {k: float(np.nanmean(d[k][inst.dom == dm])) for k in ("S", "P", "T", "GDPR", "POPIA", "NIST")}
                        for dm in DOMAINS}
    for dm in DOMAINS:
        m = inst.dom == dm
        cs = [np.nanmean(d[f_][m]) for f_ in ("GDPR", "POPIA", "NIST")]
        out["by_domain"][dm]["CS"] = float(np.nanmean(cs))
    out["adoption"] = {dm: (X[inst.dom == dm].mean(0)).round(4).tolist() for dm in DOMAINS}
    return out


def dominated_by(F, v):
    """Is objective vector v weakly dominated by some member of front F (and strictly better somewhere)?"""
    return bool(np.any(np.all(F >= v - 1e-12, axis=1) & np.any(F > v + 1e-12, axis=1)))


def one_rep(job):
    exp, arm, rep, setting, over, bfrac, full = job
    global REAL
    if REAL is None:
        REAL = {False: load_real(), True: load_real(exclude_chipset=True)}
    real = REAL[bool(over.pop("exclude_chipset", False))] if over else REAL[False]
    t0 = time.time()
    inst = Instance(seed_of(rep, arm), arm, real, over)
    B = bfrac * inst.full_cost
    tables = [inst.device_table(i) for i in range(inst.N)]
    menus = DeviceMenus(inst, tables)
    rec = dict(exp=exp, arm=arm, rep=rep, setting=setting, budget_frac=bfrac, B=float(B), V=int(inst.V))
    rec["as_is"] = summarize(inst, inst.x0)
    Z, F, _ = run_menu_moea(inst, B, seed_of(rep, arm, 7), "NSGA2", menus=menus)
    ref = np.array([rec["as_is"][o] for o in OBJ])
    rec["nsga2"] = dict(front_size=int(len(F)), hv=hypervolume(F, ref) if len(F) else 0.0)
    if len(F):
        kk = knee(F)
        rec["knee"] = summarize(inst, menus.to_X(Z[kk]))
        rec["front_objs"] = F.round(6).tolist() if full else None
    ex = []
    for w in WEIGHTS:
        e = exact_weighted(inst, B, w, tables)
        ex.append(dict(w=w, value=None if e is None else float(e["value"]),
                       best_front=None if not len(F) else float((F @ np.array(w)).max())))
    rec["exact_gap"] = ex
    if full:
        e5 = exact_weighted(inst, B, [0.25] * 4, tables)
        e3 = exact_weighted(inst, B, [0, 0, 0, 1], tables, cs_min=None)
        bl = {"B1_checklist": baseline_checklist(inst, B), "B2_greedy_security": baseline_greedy_security(inst, B),
              "B3_compliance_only": None if e3 is None else e3["X"], "B5_weighted_sum": None if e5 is None else e5["X"]}
        rec["baselines"] = {k: (None if v is None else summarize(inst, v)) for k, v in bl.items()}
        R = baseline_random(inst, B, np.random.default_rng(seed_of(rep, arm, 11)), draws=200)
        fr = inst.fleet(R)
        rec["baselines"]["B4_random"] = {k: float(np.mean(fr[k])) for k in KEYS}
        rec["baselines"]["B4_random"]["meets_cs_share"] = float(np.mean(fr["CS"] >= CS_TH - 1e-9))
        for k, v in rec["baselines"].items():
            if v is not None and len(F):
                v["dominated_by_front"] = dominated_by(F, np.array([v[o] for o in OBJ]))
    rec["seconds"] = round(time.time() - t0, 2)
    return rec


def algo_rep(job):
    exp, arm, rep, setting, over, bfrac, full = job
    global REAL
    if REAL is None:
        REAL = {False: load_real()}
    inst = Instance(seed_of(rep, arm), arm, REAL[False], over)
    B = bfrac * inst.full_cost
    tables = [inst.device_table(i) for i in range(inst.N)]
    menus = DeviceMenus(inst, tables)
    ref = np.array([inst.fleet(inst.x0)[o] for o in OBJ])
    exact = {tuple(w): exact_weighted(inst, B, w, tables)["value"] for w in WEIGHTS}
    rec = dict(exp=exp, arm=arm, rep=rep, setting=setting, budget_frac=bfrac)
    for name in ("NSGA2", "NSGA3", "MOEAD", "NSGA2_bitstring"):
        t0 = time.time()
        if name == "NSGA2_bitstring":
            X, F = run_moea(inst, B, seed_of(rep, arm, 7), "NSGA2", ratio=static_ratio(inst))
        else:
            _, F, _ = run_menu_moea(inst, B, seed_of(rep, arm, 7), name, menus=menus)
        gaps = [float((exact[tuple(w)] - (F @ np.array(w)).max()) / exact[tuple(w)]) if len(F) else None for w in WEIGHTS]
        rec[name] = dict(seconds=round(time.time() - t0, 2), front_size=int(len(F)), hv=hypervolume(F, ref) if len(F) else 0.0,
                         gaps=gaps, max_obj=F.max(0).tolist() if len(F) else None)
    return rec


def jobs_for(exp, reps):
    J = []
    bref = P["constraints"]["budget_reference"]
    if exp == "main":
        for arm in ("real", "simulated"):
            J += [(exp, arm, r, "reference", {}, bref, True) for r in range(reps or P["replications"]["R"])]
    elif exp == "sweep":
        for arm in ("real", "simulated"):
            for b in P["constraints"]["budget_fractions"]:
                J += [(exp, arm, r, f"budget={b}", {}, b, b == bref) for r in range(reps or 20)]
    elif exp == "algos":
        J += [(exp, "real", r, "reference", {}, bref, False) for r in range(reps or 20)]
    elif exp == "sensitivity":
        v = P["vulnerabilities"]; S = []
        S += [(f"lambda={x}", dict(lam=x)) for x in v["lambda_sensitivity"]]
        S += [(f"beta={x}", dict(beta=x)) for x in v["beta_sensitivity"]]
        S += [(f"rho={x}", dict(rho=x)) for x in P["ids"]["rho_sensitivity"]]
        S += [(f"effect_x{x}", dict(eff=x)) for x in P["effectiveness"]["effect_sensitivity"]]
        S += [(f"latency_caps_x{x}", dict(lat=x)) for x in (0.5, 1.5)]
        S += [(f"prevalence={x}", dict(prev=x)) for x in P["existing_controls"]["prevalence_sensitivity"]]
        rng = np.random.default_rng(99)
        S += [(f"cost_jitter_{j}", dict(cost_jitter=rng.uniform(0.5, 1.5, K).round(3).tolist())) for j in range(3)]
        for name, o in S:
            J += [(exp, "real", r, name, dict(o), bref, True) for r in range(reps or 20)]
    elif exp == "ablation":
        S = [("cve_synthetic", dict(cve="synthetic")), ("ids_synthetic", dict(ids="synthetic")),
             ("tp_synthetic", dict(tp="synthetic")), ("chipset_excluded", dict(exclude_chipset=True)),
             ("kev_off", dict(kev=1.0))]
        for name, o in S:
            J += [(exp, "real", r, name, dict(o), bref, True) for r in range(reps or 20)]
    return J


if __name__ == "__main__":
    ap = argparse.ArgumentParser(); ap.add_argument("exp"); ap.add_argument("--reps", type=int, default=None)
    ap.add_argument("--workers", type=int, default=2); ap.add_argument("--tag", default="")
    a = ap.parse_args()
    os.makedirs(OUT, exist_ok=True)
    path = os.path.join(OUT, f"{a.exp}{a.tag}.jsonl")
    done = set()
    if os.path.exists(path):
        for line in open(path):
            r = json.loads(line); done.add((r["arm"], r["rep"], r["setting"], r["budget_frac"]))
    J = [j for j in jobs_for(a.exp, a.reps) if (j[1], j[2], j[3], j[5]) not in done]
    fn = algo_rep if a.exp == "algos" else one_rep
    print(f"{a.exp}: {len(J)} jobs to run ({len(done)} already done)", flush=True)
    with Pool(a.workers) as pool, open(path, "a") as fh:
        for n, rec in enumerate(pool.imap_unordered(fn, J), 1):
            fh.write(json.dumps(rec) + "\n"); fh.flush()
            if n % 10 == 0 or n == len(J):
                print(f"  {n}/{len(J)}", flush=True)
