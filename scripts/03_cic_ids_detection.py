"""Packet-level IDS detection rates per attack category, CIC IoT-DIAD 2024 (packet-based features).

Usage: python3 03_cic_ids_detection.py <packet_features_root> <out.csv>

Design (fixed in advance):
  * Benign: four capture files, split BY FILE: BenignTraffic + BenignTraffic1 = training,
    BenignTraffic2 = threshold calibration, BenignTraffic3 = held-out false-positive check.
  * Attacks: one capture per sub-category (the smallest file, chosen mechanically). Each is split IN TIME:
    first half of rows = training, second half = test (split at row-group granularity). Up to 30,000 rows are drawn at random from each half.
  * Features: every numeric column except identifiers and ephemeral values (stream, src_port, IP/MAC/OUI strings).
  * Detector: sklearn HistGradientBoostingClassifier, benign vs attack, default hyperparameters, random_state=2026.
  * Thresholds: revision 1 (after the first run showed the calibration-file threshold gives 12.9% false positives on
    the other benign file, i.e. capture-session shift). The threshold is the larger of the two benign quantiles, so
    the FPR is at or below target on BOTH benign files. There is therefore no untouched benign file; the naive
    held-out FPR is reported alongside.
  * Reported: packet-level detection rate on each attack test half, with Wilson 95% intervals; realised FPR on
    the held-out benign file. Packet-level detection is a conservative proxy for attack-level detection.
"""
import sys, glob, os
import numpy as np, pandas as pd, pyarrow.parquet as pq
from sklearn.ensemble import HistGradientBoostingClassifier

SEED = 2026
N_PER_HALF = 30000
DROP = {"stream", "src_port"}
rng = np.random.default_rng(SEED)


def numeric_schema(path):
    import pyarrow.types as pt
    sch = pq.ParquetFile(path).schema_arrow
    return [f.name for f in sch if f.name not in DROP and (pt.is_integer(f.type) or pt.is_floating(f.type))]


def load_sampled(path, cols, n, part=None):
    """Read only `cols`; sample up to n rows. part='first'/'second' restricts to row groups in that half of the file."""
    pf = pq.ParquetFile(path)
    sizes = [pf.metadata.row_group(i).num_rows for i in range(pf.num_row_groups)]
    cum = np.cumsum(sizes); half = cum[-1] / 2
    groups = list(range(pf.num_row_groups))
    if part == "first":
        groups = [i for i in groups if cum[i] - sizes[i] < half]
    elif part == "second":
        groups = [i for i in groups if cum[i] - sizes[i] >= half] or groups[-1:]
    tot = sum(sizes[i] for i in groups)
    out = []
    for i in groups:
        k = int(round(n * sizes[i] / tot)) if tot > n else sizes[i]
        if k == 0:
            continue
        t = pf.read_row_group(i, columns=cols).to_pandas()
        out.append(t.iloc[rng.choice(len(t), size=min(k, len(t)), replace=False)] if k < len(t) else t)
    return pd.concat(out).astype("float32")


def numeric_cols(df):
    return [c for c in df.columns if c not in DROP and pd.api.types.is_numeric_dtype(df[c])]


def wilson(k, n, z=1.96):
    if n == 0:
        return (np.nan, np.nan)
    p = k / n; d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d; h = z * np.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (c - h, c + h)


def sample(df, n):
    return df.iloc[rng.choice(len(df), size=min(n, len(df)), replace=False)] if len(df) > n else df


if __name__ == "__main__":
    root, outp = sys.argv[1:3]
    bdir = os.path.join(root, "BenignTraffic")
    afiles = [f for f in sorted(glob.glob(os.path.join(root, "*", "*", "*.parquet"))) if "BenignTraffic" not in f]
    bfiles = {f: os.path.join(bdir, f + ".parquet") for f in ("BenignTraffic", "BenignTraffic1", "BenignTraffic2", "BenignTraffic3")}
    feats = set(numeric_schema(bfiles["BenignTraffic"]))
    for f in list(bfiles.values()) + afiles:
        feats &= set(numeric_schema(f))
    feats = sorted(feats)
    Xb = pd.concat([load_sampled(bfiles[f], feats, 3 * N_PER_HALF) for f in ("BenignTraffic", "BenignTraffic1")])
    bcal = load_sampled(bfiles["BenignTraffic2"], feats, 10 ** 9)
    btest = load_sampled(bfiles["BenignTraffic3"], feats, 10 ** 9)
    atk_train, atk_test = [], {}
    for f in afiles:
        cat, sub = f.split(os.sep)[-3], f.split(os.sep)[-2]
        atk_train.append(load_sampled(f, feats, N_PER_HALF, "first"))
        atk_test[(cat, sub)] = load_sampled(f, feats, N_PER_HALF, "second")
    X = pd.concat([Xb[feats], pd.concat(atk_train)[feats]]).astype(float)
    y = np.r_[np.zeros(len(Xb)), np.ones(len(X) - len(Xb))]
    clf = HistGradientBoostingClassifier(random_state=SEED).fit(X, y)
    s_cal = clf.predict_proba(bcal[feats].astype(float))[:, 1]
    s_bt = clf.predict_proba(btest[feats].astype(float))[:, 1]
    rows = []
    for fpr in (0.01, 0.05):
        thr_naive = np.quantile(s_cal, 1 - fpr)
        naive_fpr = float((s_bt > thr_naive).mean())          # reported: the threshold does not transfer
        thr = max(thr_naive, np.quantile(s_bt, 1 - fpr))       # conservative: FPR <= target on both benign files
        realised = max(float((s_cal > thr).mean()), float((s_bt > thr).mean()))
        for (cat, sub), d in atk_test.items():
            s = clf.predict_proba(d[feats].astype(float))[:, 1]
            k, n = int((s > thr).sum()), len(s)
            lo, hi = wilson(k, n)
            rows.append(dict(target_fpr=fpr, naive_threshold_heldout_fpr=naive_fpr, realised_fpr_max=realised, category=cat, subcategory=sub,
                             n_test=n, detected=k, dr=k / n, dr_lo=lo, dr_hi=hi))
    out = pd.DataFrame(rows)
    out.to_csv(outp, index=False)
    print("features", len(feats), "| benign train", len(Xb), "| attack train", len(X) - len(Xb))
    print(out.groupby(["target_fpr", "category"]).agg(dr=("dr", "mean"), dr_min=("dr", "min"),
                                                      fpr=("realised_fpr_max", "first"), naive=("naive_threshold_heldout_fpr", "first")).round(3))
