"""Compliance-aware multi-objective control selection for consumer IoT fleets (IJSP revision).

Decision variables  x[i,k] in {0,1}: deploy control k on device i (N devices x K controls).
Objectives (maximise, fleet means): S (security), P (privacy), T (trust proxies), CS (compliance coverage).
Constraints: per-device latency and throughput caps; fleet budget; fleet compliance threshold.

Every formula below is numbered as in the manuscript (Eq. n).
"""
import json, os, itertools
import numpy as np
import pandas as pd

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
P = json.load(open(os.path.join(ROOT, "params.json")))
DOMAINS = P["fleet"]["domains"]
CTRL = [c["id"] for c in P["controls"]["list"]]
K = len(CTRL)
KI = {k: j for j, k in enumerate(CTRL)}
CLASSES = P["weakness_classes"]["order"] + ["OTHER"]
AVS = ["NETWORK", "ADJACENT_NETWORK", "LOCAL", "PHYSICAL"]
IMP = P["vulnerabilities"]["cvss_impact"]


# ----------------------------------------------------------------------------------------------- data inputs
def cwe_class(cwes):
    lut = {}
    for c in P["weakness_classes"]["order"]:
        for n in P["weakness_classes"][c]:
            lut.setdefault(n, c)
    if not isinstance(cwes, str):
        return "OTHER"
    ids = {int(x[4:]) for x in cwes.split("|") if x[4:].isdigit()}
    for c in P["weakness_classes"]["order"]:
        if any(lut.get(i) == c for i in ids):
            return c
    return "OTHER"


def load_real(data_dir=os.path.join(ROOT, "data"), exclude_chipset=False):
    nvd = pd.read_csv(os.path.join(data_dir, "nvd_ciot.csv"))
    nvd = nvd[nvd.cvss_src != "none"].copy()
    if exclude_chipset:
        nvd = nvd[~nvd.chipset]
    nvd["wclass"] = nvd.cwes.map(cwe_class)
    tp = pd.read_csv(os.path.join(data_dir, "cic_transfer_protection.csv"))
    tp = tp[tp.calibration_use].enc_share_bytes.to_numpy()
    ids = pd.read_csv(os.path.join(data_dir, "cic_ids_detection.csv"))
    ids = ids[ids.target_fpr == 0.01].groupby("category").dr.mean().to_dict()
    return dict(nvd=nvd, tp=tp, ids=ids)


# ----------------------------------------------------------------------------------------------- instance
class Instance:
    """One sampled fleet. arm='real' draws device states from data; arm='simulated' from stated uniform ranges.
    `over` holds sensitivity / ablation overrides."""

    def __init__(self, seed, arm="real", real=None, over=None):
        o = dict(lam=P["vulnerabilities"]["lambda_per_device"], beta=P["vulnerabilities"]["beta_exploit"],
                 kev=P["vulnerabilities"]["kev_multiplier"], rho=P["ids"]["rho_response"], eff=1.0, lat=1.0,
                 cve="real" if arm == "real" else "synthetic", ids="real" if arm == "real" else "synthetic",
                 tp="real" if arm == "real" else "synthetic", cost_jitter=None,
                 prev=P["existing_controls"]["prevalence"])
        o.update(over or {})
        self.o, self.arm, self.seed = o, arm, seed
        rng = np.random.default_rng(seed)
        self.dom = np.array([d for d in DOMAINS for _ in range(P["fleet"]["devices"][d])])
        self.N = N = len(self.dom)
        self.dix = np.array([DOMAINS.index(d) for d in self.dom])

        # ---- vulnerabilities
        n_v = rng.poisson(o["lam"], size=N)
        rows = []
        if o["cve"] == "real":
            nvd = real["nvd"]; pools = {d: nvd[nvd.domain == d] for d in DOMAINS}; n0 = P["vulnerabilities"]["shrinkage_n0"]
            for i in range(N):
                pool = pools[self.dom[i]]; w = len(pool) / (len(pool) + n0)
                for _ in range(n_v[i]):
                    src = pool if rng.random() < w else nvd
                    r = src.iloc[rng.integers(len(src))]
                    rows.append((i, r.wclass, r.av, IMP[r.c], IMP[r.i], IMP[r.a], r.expl, bool(r.kev)))
        else:
            s = P["vulnerabilities"]["synthetic"]
            for i in range(N):
                for _ in range(n_v[i]):
                    c, ii, a = rng.choice(s["impact_levels"], 3)
                    rows.append((i, CLASSES[rng.integers(len(CLASSES))], s["attack_vectors"][rng.integers(4)],
                                 IMP[c], IMP[ii], IMP[a], rng.uniform(*s["expl_range"]), rng.random() < s["kev_prob"]))
        v = pd.DataFrame(rows, columns=["dev", "wclass", "av", "c", "i", "a", "expl", "kev"])
        self.V = len(v)
        self.vdev = v.dev.to_numpy(int)
        self.vcls = v.wclass.to_numpy()
        self.vav = v.av.to_numpy()
        n = 0.56
        self.vc, self.vi, self.va = v.c.to_numpy() / n, v.i.to_numpy() / n, v.a.to_numpy() / n
        mult = np.where(v.kev.to_numpy(), o["kev"], 1.0)
        self.vp = np.minimum(1.0, o["beta"] * v.expl.to_numpy() / 3.9 * mult)            # Eq. (1)
        self.vnet = np.isin(self.vav, ["NETWORK", "ADJACENT_NETWORK"])
        self.vtransit = self.vcls == "TRANSIT"
        self.vstore = np.isin(self.vcls, ["STORAGE", "ACCESS"])
        # one-hot device map (V x N) for segment products
        self.M = np.zeros((self.V, N)); self.M[np.arange(self.V), self.vdev] = 1.0

        # ---- effectiveness matrix E (V x K): probability control k neutralises vulnerability v
        ids_dr = real["ids"] if (o["ids"] == "real") else None
        E = np.zeros((self.V, K))
        eff = P["effectiveness"]
        for vi_ in range(self.V):
            cl, av = self.vcls[vi_], self.vav[vi_]
            for k in CTRL:
                e = 0.0; spec = eff.get(k, {})
                if k == "k3": e = spec["ALL"]
                elif k == "k10": e = spec["ALL"]
                elif k == "k6": e = spec["ALL_BY_AV"].get(av, 0.0)
                elif k == "k7":
                    if av in P["ids"]["_av"]:
                        cats = P["ids"]["class_to_cic"][cl]
                        dr = (np.mean([ids_dr[c] for c in cats]) if cats else 0.0) if ids_dr is not None else \
                             (P["ids"]["synthetic_detection"] if cats else 0.0)
                        e = dr * o["rho"]
                elif k == "k8": e = spec.get(cl, 0.0) if av in spec["_av"] else 0.0
                elif k in ("k1", "k2", "k4", "k5"): e = spec.get(cl, 0.0)
                E[vi_, KI[k]] = min(0.99, e * o["eff"])
        self.LE = np.log1p(-E)                                                            # V x K
        self.k11A = min(0.99, eff["k11"]["AVAILABILITY_ONLY"] * o["eff"])

        # ---- privacy baselines
        pr = P["privacy"]
        self.sigma = np.array([pr["collection_exposure"][d] for d in self.dom])
        if o["tp"] == "real":
            self.tpb = real["tp"][rng.integers(len(real["tp"]), size=N)]
        else:
            self.tpb = rng.uniform(*pr["tp_baseline_synthetic"], size=N)

        # ---- resources
        cl = P["controls"]["list"]
        base_cost = np.array([c["cost"] for c in cl], float)
        if o["cost_jitter"] is not None:
            base_cost = base_cost * o["cost_jitter"]
        self.cost = np.outer([P["controls"]["domain_cost_factor"][d] for d in self.dom], base_cost)   # N x K
        self.lat = np.array([c["lat"] for c in cl], float)
        self.lthr = np.log1p(-np.array([c["thr"] for c in cl], float))
        self.Lmax = np.array([P["constraints"]["latency_max_ms"][d] for d in self.dom]) * o["lat"]
        self.Tmin = np.array([P["constraints"]["throughput_min"][d] for d in self.dom])
        # ---- existing (as-is) controls: sunk, never removed
        x0 = (rng.random((N, K)) < o["prev"]).astype(float)
        if o["tp"] == "real":
            x0[:, KI["k4"]] = (self.tpb >= 0.9).astype(float)
        order = np.argsort(-(self.lat - 50 * self.lthr))           # drop highest-latency/throughput first
        for i in range(N):
            for j in order:
                if (x0[i] @ self.lat <= self.Lmax[i] + 1e-9) and (np.exp(x0[i] @ self.lthr) >= self.Tmin[i] - 1e-9):
                    break
                x0[i, j] = 0
        self.x0 = x0
        self.full_cost = (self.cost * (1 - x0)).sum()             # cost of adding every missing control

        # ---- compliance requirements -> (framework, applicable device mask, rule)
        self.reqs = []
        for fw in ("GDPR", "POPIA", "NIST"):
            for r in P["compliance"][fw]:
                app = np.ones(N, bool)
                if "domains" in r:
                    app &= np.isin(self.dom, r["domains"])
                if fw in ("GDPR", "POPIA") and not P["compliance"]["GDPR_POPIA_apply_to_industrial"]:
                    app &= self.dom != "industrial"
                self.reqs.append((fw, r["id"], app, r["rule"]))

    # ------------------------------------------------------------------------------------------- evaluation
    def rule(self, X, rule):
        """Evaluate a requirement rule such as 'k3&k1&(k4|k5)' on X (... x K) -> bool (...)."""
        expr = rule
        for k in sorted(CTRL, key=len, reverse=True):
            expr = expr.replace(k, f"B[{KI[k]}]")
        B = [X[..., j].astype(bool) for j in range(K)]
        return eval(expr.replace("&", " & ").replace("|", " | "), {"B": B})

    def device_scores(self, X):
        """X: (..., N, K) binary. Returns dict of per-device component arrays (..., N). Eqs. (2)-(13)."""
        X = np.asarray(X, float)
        Xv = X[..., self.vdev, :]                                   # (..., V, K)
        logm = (Xv * self.LE).sum(-1)                               # Eq. (2): log prod_k (1 - x e)
        m = np.exp(logm)
        mA = m * (1 - X[..., self.vdev, KI["k11"]] * self.k11A)    # resilience reduces availability loss only
        def seg(logterm):                                          # product over a device's vulnerabilities
            return np.exp(logterm @ self.M)
        C = seg(np.log1p(-self.vp * self.vc * m))                  # Eq. (3)
        I = seg(np.log1p(-self.vp * self.vi * m))                  # Eq. (4)
        A = seg(np.log1p(-self.vp * self.va * mA))                 # Eq. (5)
        S = (C + I + A) / 3                                        # Eq. (6)
        pr = P["privacy"]
        x = lambda k: X[..., KI[k]]
        CP = 1 - self.sigma * (1 - pr["k9_effect"] * x("k9"))      # Eq. (7)
        SP = (1 - pr["storage_exposure"] * (1 - pr["k5_storage_effect"] * x("k5"))) * \
             seg(np.log1p(-self.vp * self.vc * m * self.vstore))   # Eq. (8)
        TPc = self.tpb + x("k4") * np.maximum(0, pr["tp_after_k4"] - self.tpb)
        TP = TPc * seg(np.log1p(-self.vp * self.vc * m * self.vtransit))   # Eq. (9)
        Pv = (CP + SP + TP) / 3                                    # Eq. (10)
        TD = 0.5 * I + 0.5 * (0.4 + 0.6 * x("k3"))                 # Eq. (11)
        reach = seg(np.log1p(-self.vp * m * self.vnet))
        TN = 0.5 * TP + 0.5 * reach
        TCB = 0.4 + 0.2 * (x("k9") + x("k10") + x("k12"))
        T = (TD + TN + TCB) / 3                                    # Eq. (12)
        fw = {}
        for f in ("GDPR", "POPIA", "NIST"):
            rs = [(app, r) for (ff, _, app, r) in self.reqs if ff == f]
            num = sum(np.where(app, self.rule(X, r), 0) for app, r in rs)
            den = sum(app.astype(float) for app, _ in rs)
            fw[f] = np.where(den > 0, num / np.maximum(den, 1), np.nan)    # Eq. (13)
        return dict(C=C, I=I, A=A, S=S, CP=CP, SP=SP, TP=TP, P=Pv, TD=TD, TN=TN, TCB=TCB, T=T, **fw)

    def fleet(self, X):
        """Fleet objectives (Eq. 14): means over devices; CS = mean of the three framework means over applicable devices."""
        d = self.device_scores(X)
        out = {k: d[k].mean(-1) for k in ("C", "I", "A", "S", "CP", "SP", "TP", "P", "TD", "TN", "TCB", "T")}
        for f in ("GDPR", "POPIA", "NIST"):
            out[f] = np.nanmean(d[f], axis=-1)
        out["CS"] = (out["GDPR"] + out["POPIA"] + out["NIST"]) / 3
        return out

    def resources(self, X):
        X = np.asarray(X, float)
        cost = (X * (1 - self.x0) * self.cost).sum((-1, -2))      # only added controls cost money
        lat = X @ self.lat
        thr = np.exp(X @ self.lthr)
        return cost, lat, thr

    def feasible_device(self, X):
        _, lat, thr = self.resources(X)
        return (lat <= self.Lmax + 1e-9) & (thr >= self.Tmin - 1e-9)

    # ------------------------------------------------------------------------------------------- enumeration
    def configs(self):
        """All 2^K configurations (4096 x K)."""
        if not hasattr(self, "_cfg"):
            self._cfg = np.array(list(itertools.product([0, 1], repeat=K)), np.int8)
        return self._cfg

    def sub(self, i):
        """A one-device view of this instance (same equations, same parameters)."""
        import copy
        o = copy.copy(self)
        sel = self.vdev == i
        o.N = 1; o.dom = self.dom[i:i + 1]; o.dix = self.dix[i:i + 1]
        o.V = int(sel.sum()); o.vdev = np.zeros(o.V, int)
        for a in ("vcls", "vav", "vc", "vi", "va", "vp", "vnet", "vtransit", "vstore", "LE"):
            setattr(o, a, getattr(self, a)[sel])
        o.M = np.ones((o.V, 1))
        o.sigma = self.sigma[i:i + 1]; o.tpb = self.tpb[i:i + 1]
        o.cost = self.cost[i:i + 1]; o.x0 = self.x0[i:i + 1]; o.Lmax = self.Lmax[i:i + 1]; o.Tmin = self.Tmin[i:i + 1]
        o.reqs = [(f, rid, app[i:i + 1], r) for (f, rid, app, r) in self.reqs]
        return o

    def n_applicable(self):
        return {f: int(np.any([app for (ff, _, app, _) in self.reqs if ff == f], axis=0).sum()) for f in ("GDPR", "POPIA", "NIST")}

    def device_table(self, i):
        """Every feasible configuration of device i, its cost, and its contribution to each fleet objective
        (contributions summed over devices equal the fleet values of Eq. 14)."""
        cfg = self.configs()
        lat = cfg @ self.lat; thr = np.exp(cfg @ self.lthr)
        cfg = cfg[(lat <= self.Lmax[i] + 1e-9) & (thr >= self.Tmin[i] - 1e-9) & np.all(cfg >= self.x0[i], axis=1)]
        o = self.sub(i)
        d = o.device_scores(cfg[:, None, :])
        contrib = {k: d[k][:, 0] / self.N for k in ("S", "P", "T")}
        napp = self.n_applicable()
        cs = np.zeros(len(cfg))
        for f in ("GDPR", "POPIA", "NIST"):
            v = d[f][:, 0]
            if not np.isnan(v[0]):
                cs += v / napp[f] / 3
        contrib["CS"] = cs
        return cfg, cfg @ (self.cost[i] * (1 - self.x0[i])), contrib
