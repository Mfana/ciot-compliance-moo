"""Optimisers and comparison baselines for the IJSP revision."""
import numpy as np
from scipy.optimize import milp, LinearConstraint, Bounds
from scipy.sparse import lil_matrix, csr_matrix
from pymoo.core.problem import Problem
from pymoo.core.repair import Repair
from pymoo.core.sampling import Sampling
from pymoo.algorithms.moo.nsga2 import NSGA2
from pymoo.algorithms.moo.nsga3 import NSGA3
from pymoo.algorithms.moo.moead import MOEAD
from pymoo.operators.crossover.ux import UniformCrossover
from pymoo.operators.mutation.bitflip import BitflipMutation
from pymoo.util.ref_dirs import get_reference_directions
from pymoo.indicators.hv import HV
from pymoo.optimize import minimize
from .model import K, KI, P

OBJ = ("S", "P", "T", "CS")
CS_TH = P["constraints"]["compliance_threshold"]


# ----------------------------------------------------------------------------------------------- helpers
def static_ratio(inst):
    """Value-per-cost of adding control k alone to device i on top of its as-is controls (equal-weight composite).
    Used only to order removals in the budget repair and by the greedy baselines."""
    base = inst.fleet(inst.x0)
    comp0 = sum(base[o] for o in OBJ) / 4
    r = np.full((inst.N, K), np.inf)
    for i in range(inst.N):
        for k in range(K):
            if inst.x0[i, k]:
                continue
            X = inst.x0.copy(); X[i, k] = 1
            f = inst.fleet(X)
            r[i, k] = (sum(f[o] for o in OBJ) / 4 - comp0) / inst.cost[i, k]
    return r


def device_repair(inst, X):
    """X: (pop, N, K). Enforce x >= x0, then per-device latency/throughput caps by dropping added controls,
    heaviest resource user first."""
    X = np.maximum(X, inst.x0[None])
    order = np.argsort(-(inst.lat / 12 - inst.lthr * 10))
    for j in order:
        bad = ~inst.feasible_device(X)
        if not bad.any():
            break
        drop = bad & (X[..., j] == 1) & (inst.x0[None, :, j] == 0)
        X[..., j][drop] = 0
    return X


def budget_repair(inst, X, B, ratio):
    cost, _, _ = inst.resources(X)
    flat_r = ratio.ravel()
    for p in np.where(cost > B + 1e-9)[0]:
        added = np.where((X[p].ravel() == 1) & (inst.x0.ravel() == 0))[0]
        added = added[np.argsort(flat_r[added])]
        c = cost[p]; costs = inst.cost.ravel()
        for idx in added:
            if c <= B + 1e-9:
                break
            X[p].reshape(-1)[idx] = 0; c -= costs[idx]
    return X


# ----------------------------------------------------------------------------------------------- pymoo problem
class FleetProblem(Problem):
    def __init__(self, inst, B):
        self.inst, self.B = inst, B
        super().__init__(n_var=inst.N * K, n_obj=4, n_ieq_constr=2, xl=0, xu=1, vtype=bool)

    def _evaluate(self, x, out, *args, **kwargs):
        X = x.reshape(len(x), self.inst.N, K).astype(float)
        f = self.inst.fleet(X)
        cost, _, _ = self.inst.resources(X)
        out["F"] = -np.column_stack([f[o] for o in OBJ])
        out["G"] = np.column_stack([cost - self.B, CS_TH - f["CS"]])


class FleetRepair(Repair):
    def __init__(self, inst, B, ratio):
        super().__init__(); self.inst, self.B, self.ratio = inst, B, ratio

    def _do(self, problem, x, **kwargs):
        X = x.reshape(len(x), self.inst.N, K).astype(float)
        X = budget_repair(self.inst, device_repair(self.inst, X), self.B, self.ratio)
        return X.reshape(len(x), -1).astype(bool)


class FleetSampling(Sampling):
    def __init__(self, inst):
        super().__init__(); self.inst = inst

    def _do(self, problem, n_samples, random_state=None, **kwargs):
        rng = random_state if random_state is not None else np.random.default_rng()
        dens = rng.uniform(0, 1, size=(n_samples, 1))
        x = rng.random((n_samples, problem.n_var)) < dens
        x[0] = self.inst.x0.ravel().astype(bool)
        return x


def run_moea(inst, B, seed, algo="NSGA2", pop=None, gens=None, ratio=None):
    pop = pop or P["optimizer"]["pop_size"]; gens = gens or P["optimizer"]["generations"]
    ratio = static_ratio(inst) if ratio is None else ratio
    prob = FleetProblem(inst, B)
    common = dict(sampling=FleetSampling(inst), crossover=UniformCrossover(prob=0.9),
                  mutation=BitflipMutation(prob=1.0, prob_var=1.0 / prob.n_var), repair=FleetRepair(inst, B, ratio))
    if algo == "NSGA2":
        alg = NSGA2(pop_size=pop, eliminate_duplicates=True, **common)
    elif algo == "NSGA3":
        rd = get_reference_directions("das-dennis", 4, n_partitions=7)       # 120 directions
        alg = NSGA3(ref_dirs=rd, pop_size=pop, eliminate_duplicates=True, **common)
    elif algo == "MOEAD":
        rd = get_reference_directions("das-dennis", 4, n_partitions=7)
        common.pop("sampling")
        alg = MOEAD(ref_dirs=rd, n_neighbors=15, prob_neighbor_mating=0.7, sampling=FleetSampling(inst), **{k: v for k, v in common.items()})
    res = minimize(prob, alg, ("n_gen", gens), seed=int(seed % (2 ** 31)), verbose=False, save_history=False)
    X = np.atleast_2d(res.X).reshape(-1, inst.N, K).astype(float)
    F = -np.atleast_2d(res.F)
    feas = np.all(np.atleast_2d(res.G) <= 1e-9, axis=1) if res.G is not None else np.ones(len(F), bool)
    return X[feas], F[feas]


def knee(F):
    lo, hi = F.min(0), F.max(0)
    Z = (F - lo) / np.where(hi > lo, hi - lo, 1)
    return int(np.argmin(np.linalg.norm(1 - Z, axis=1)))


def hypervolume(F, ref):
    """Hypervolume of maximisation front F above reference point ref (the as-is objective vector)."""
    G = -(F - ref)
    G = G[np.all(G < 0, axis=1)]
    return float(HV(ref_point=np.zeros(4))(G)) if len(G) else 0.0


# ----------------------------------------------------------------------------------------------- exact MILP
def exact_weighted(inst, B, w, tables=None, cs_min=CS_TH, time_limit=120):
    """Exact maximiser of sum_o w_o * F_o subject to the budget and fleet-compliance constraints:
    a multiple-choice knapsack over every device's enumerated feasible configurations, solved by HiGHS."""
    tables = tables or [inst.device_table(i) for i in range(inst.N)]
    cols, vals, costs, css, owner = [], [], [], [], []
    for i, (cfg, cost, con) in enumerate(tables):
        v = sum(w[j] * con[o] for j, o in enumerate(OBJ))
        cs = con["CS"]
        # keep configurations not dominated in (cost low, value high, cs high)
        o = np.lexsort((-cs, -v, cost)); keep = []
        for a in o:
            if all(not (cost[b] <= cost[a] and v[b] >= v[a] and cs[b] >= cs[a]) for b in keep[-400:]):
                keep.append(a)
        keep = np.array(keep)
        cols.append(cfg[keep]); vals.append(v[keep]); costs.append(cost[keep]); css.append(cs[keep]); owner.append(np.full(len(keep), i))
    v = np.concatenate(vals); c = np.concatenate(costs); cs = np.concatenate(css); own = np.concatenate(owner)
    n = len(v)
    A = lil_matrix((inst.N + 2, n))
    A[own, np.arange(n)] = 1
    A[inst.N, :] = c
    A[inst.N + 1, :] = cs
    lb = np.r_[np.ones(inst.N), -np.inf, cs_min if cs_min is not None else -np.inf]
    ub = np.r_[np.ones(inst.N), B, np.inf]
    res = milp(-v, constraints=LinearConstraint(csr_matrix(A), lb, ub), integrality=np.ones(n), bounds=Bounds(0, 1),
               options=dict(time_limit=time_limit, mip_rel_gap=1e-7))
    if res.x is None:
        return None
    y = res.x > 0.5
    X = np.concatenate(cols)[y][np.argsort(own[y])].astype(float)
    return dict(X=X, value=-res.fun, status=res.status, n_vars=n, gap=getattr(res, "mip_gap", None))


# ----------------------------------------------------------------------------------------------- baselines
ETSI_ORDER = [KI[k] for k in ("k1", "k12", "k3", "k5", "k4", "k8", "k9", "k10", "k6", "k11", "k7", "k2")]


def baseline_checklist(inst, B):
    X = inst.x0.copy(); spent = 0.0
    for j in ETSI_ORDER:
        for i in range(inst.N):
            if X[i, j] or spent + inst.cost[i, j] > B + 1e-9:
                continue
            X[i, j] = 1
            if _dev_ok(inst, X, i):
                spent += inst.cost[i, j]
            else:
                X[i, j] = 0
    return X


def _dev_ok(inst, X, i):
    return (X[i] @ inst.lat <= inst.Lmax[i] + 1e-9) and (np.exp(X[i] @ inst.lthr) >= inst.Tmin[i] - 1e-9)


def baseline_greedy_security(inst, B):
    """Repeatedly add the single (device, control) with the largest fleet-security gain per unit cost.
    Fleet security is a mean of device scores, so a candidate's gain depends only on its own device."""
    X = inst.x0.copy(); spent = 0.0
    subs = [inst.sub(i) for i in range(inst.N)]
    def gains(i):
        cand = np.repeat(X[i][None], K, 0); cand[np.arange(K), np.arange(K)] = 1
        s = subs[i].device_scores(cand[:, None, :])["S"][:, 0]
        s0 = subs[i].device_scores(X[i][None, None, :])["S"][0, 0]
        ok = (cand @ inst.lat <= inst.Lmax[i] + 1e-9) & (np.exp(cand @ inst.lthr) >= inst.Tmin[i] - 1e-9) & (X[i] == 0)
        return np.where(ok, (s - s0) / inst.N / inst.cost[i], -np.inf)
    G = np.array([gains(i) for i in range(inst.N)])
    while True:
        G[inst.cost + spent > B + 1e-9] = -np.inf
        i, k = np.unravel_index(np.argmax(G), G.shape)
        if not np.isfinite(G[i, k]) or G[i, k] <= 1e-15:
            break
        X[i, k] = 1; spent += inst.cost[i, k]; G[i] = gains(i)
    return X


def baseline_random(inst, B, rng, draws=200):
    out = []
    for _ in range(draws):
        X = inst.x0.copy(); spent = 0.0
        for idx in rng.permutation(inst.N * K):
            i, k = divmod(idx, K)
            if X[i, k] or spent + inst.cost[i, k] > B + 1e-9:
                continue
            X[i, k] = 1
            if _dev_ok(inst, X, i):
                spent += inst.cost[i, k]
            else:
                X[i, k] = 0
        out.append(X)
    return np.array(out)


# ----------------------------------------------------------------------------------------------- device-level encoding
from pymoo.core.mutation import Mutation
from pymoo.util.nds.non_dominated_sorting import NonDominatedSorting


class DeviceMenus:
    """Per device: the configurations that are feasible (caps, x >= x0) and not dominated in
    (cost, S, P, T, CS contribution). Any fleet solution using a dominated configuration can be improved or matched
    by swapping it, so restricting to menus loses no Pareto-optimal fleet."""

    def __init__(self, inst, tables=None):
        tables = tables or [inst.device_table(i) for i in range(inst.N)]
        self.cfg, self.cost, self.V = [], [], []
        nds = NonDominatedSorting()
        for cfg, cost, con in tables:
            F = np.column_stack([cost] + [-con[o] for o in OBJ])
            keep = nds.do(F, only_non_dominated_front=True)
            keep = keep[np.argsort(cost[keep], kind="stable")]
            self.cfg.append(cfg[keep]); self.cost.append(cost[keep])
            self.V.append(np.column_stack([con[o][keep] for o in OBJ]))
        self.n = np.array([len(c) for c in self.cfg])
        L = self.n.max(); N = inst.N
        self.Vpad = np.full((N, L, 4), -1e9); self.Cpad = np.full((N, L), 1e18)
        for i in range(N):
            self.Vpad[i, :self.n[i]] = self.V[i]; self.Cpad[i, :self.n[i]] = self.cost[i]
        # for budget repair: for each (device, option) the best cheaper option by equal-weight value
        comp = self.Vpad.mean(-1)
        self.down = np.full((N, L), -1)
        for i in range(N):
            best = -1
            for j in range(self.n[i]):
                self.down[i, j] = best
                if best < 0 or comp[i, j] > comp[i, best]:
                    best = j
        self.comp = comp

    def objs(self, Z):
        Z = np.asarray(Z, int)
        return self.Vpad[np.arange(Z.shape[1])[None, :], Z].sum(1)       # (pop, 4)

    def costs(self, Z):
        return self.Cpad[np.arange(Z.shape[1])[None, :], np.asarray(Z, int)].sum(1)

    def to_X(self, z):
        return np.array([self.cfg[i][int(j)] for i, j in enumerate(z)], float)

    def repair(self, Z, B):
        Z = np.asarray(Z, int).copy(); rows = np.arange(Z.shape[1])[None, :]
        for _ in range(10 * Z.shape[1]):
            over = self.costs(Z) > B + 1e-9
            if not over.any():
                break
            Zo = Z[over]; d = self.down[rows, Zo]
            dv = self.comp[rows, Zo] - np.where(d >= 0, self.comp[rows, np.maximum(d, 0)], np.inf)
            dc = self.Cpad[rows, Zo] - np.where(d >= 0, self.Cpad[rows, np.maximum(d, 0)], 0)
            ratio = np.where((d >= 0) & (dc > 0), dv / np.maximum(dc, 1e-12), np.inf)
            j = ratio.argmin(1)
            Zo[np.arange(len(Zo)), j] = d[np.arange(len(Zo)), j]
            Z[over] = Zo
        return Z


class MenuProblem(Problem):
    """penalty=True (MOEA/D, which in pymoo takes no constraints): the budget is guaranteed by the repair, and a
    compliance shortfall is subtracted from every objective with weight 10."""

    def __init__(self, menus, B, penalty=False):
        self.m, self.B, self.penalty = menus, B, penalty
        super().__init__(n_var=len(menus.n), n_obj=4, n_ieq_constr=0 if penalty else 2, xl=0, xu=menus.n - 1, vtype=int)

    def _evaluate(self, x, out, *args, **kwargs):
        Z = np.round(x).astype(int)
        F = self.m.objs(Z)
        if self.penalty:
            out["F"] = -(F - 10 * np.maximum(0, CS_TH - F[:, 3:4]))
        else:
            out["F"] = -F
            out["G"] = np.column_stack([self.m.costs(Z) - self.B, CS_TH - F[:, 3]])


class MenuRepair(Repair):
    def _do(self, problem, x, **kwargs):
        return problem.m.repair(np.clip(np.round(x), 0, problem.m.n - 1), problem.B)


class MenuSampling(Sampling):
    def _do(self, problem, n_samples, random_state=None, **kwargs):
        rng = random_state if random_state is not None else np.random.default_rng()
        u = rng.random((n_samples, problem.n_var)) ** rng.uniform(0.3, 3, size=(n_samples, 1))
        Z = np.floor(u * problem.m.n).astype(int)
        Z[0] = 0                                                          # the as-is fleet
        return Z


class MenuMutation(Mutation):
    """Per device with probability 1/N: half the time a uniformly random option, half the time a step of +-1..3."""

    def _do(self, problem, X, random_state=None, **kwargs):
        rng = random_state if random_state is not None else np.random.default_rng()
        X = np.round(X).astype(int); n = problem.m.n
        hit = rng.random(X.shape) < 1.0 / X.shape[1]
        jump = rng.random(X.shape) < 0.5
        rnd = np.floor(rng.random(X.shape) * n).astype(int)
        step = X + rng.choice([-3, -2, -1, 1, 2, 3], size=X.shape)
        new = np.where(jump, rnd, np.clip(step, 0, n - 1))
        return np.where(hit, new, X)


def run_menu_moea(inst, B, seed, algo="NSGA2", pop=None, gens=None, menus=None):
    pop = pop or P["optimizer"]["pop_size"]; gens = gens or P["optimizer"]["generations"]
    menus = menus or DeviceMenus(inst)
    prob = MenuProblem(menus, B, penalty=(algo == "MOEAD"))
    common = dict(sampling=MenuSampling(), crossover=UniformCrossover(prob=0.9), mutation=MenuMutation(), repair=MenuRepair())
    if algo == "NSGA2":
        alg = NSGA2(pop_size=pop, eliminate_duplicates=True, **common)
    else:
        rd = get_reference_directions("das-dennis", 4, n_partitions=7)
        alg = (NSGA3(ref_dirs=rd, pop_size=pop, eliminate_duplicates=True, **common) if algo == "NSGA3" else
               MOEAD(ref_dirs=rd, n_neighbors=15, prob_neighbor_mating=0.7, **common))
    res = minimize(prob, alg, ("n_gen", gens), seed=int(seed % (2 ** 31)), verbose=False)
    Z = np.atleast_2d(np.round(res.X)).astype(int)
    F = menus.objs(Z)
    feas = (menus.costs(Z) <= B + 1e-6) & (F[:, 3] >= CS_TH - 1e-9)
    Z, F = Z[feas], F[feas]
    nd = NonDominatedSorting().do(-F, only_non_dominated_front=True) if len(F) else np.array([], int)
    return Z[nd], F[nd], menus
