# Pre-specified protocol: compliance-aware multi-objective control selection for consumer IoT (IJSP revision)

Frozen before any of experiments E1-E5 was run. The SHA-256 of every file listed at the end was recorded at freeze in
`FREEZE.sha256`. Any later change is logged under "Post-freeze log" with its reason.

## 1. Purpose
Answer the reviewers of the IJSP submission. The submitted manuscript compared a synthetic baseline with a synthetic
"enhanced" scenario whose values were drawn from higher ranges, without an optimiser. This study replaces that design with
(a) explicit decision variables, objectives and constraints, (b) an actual multi-objective optimiser (NSGA-II) whose
results are checked against an exact solver, (c) comparison with five alternative selection approaches at equal cost,
(d) two arms: a simulated arm (all device states from stated ranges) and a real-data arm (device states from public data),
and (e) full statistics, sensitivity and ablation analyses.

## 2. What is and is not guaranteed by construction (circularity statement)
Adding a control never lowers any score (all effects are non-negative), so any solution with positive spend improves on
the as-is fleet. Improvement over the as-is fleet is therefore reported only descriptively. The inferential comparisons
are between selection approaches **at the same budget**, where no approach is favoured by construction, and between the
simulated and real-data arms.

## 3. Model (all parameters in `params.json`, each tagged measured / standard / assumed)
* Fleet: 100 devices in five domains (30 smart home, 20 healthcare, 20 wearable, 15 vehicle, 15 industrial).
* Each device has n ~ Poisson(5) open vulnerabilities. Real arm: whole NVD records (2021-2025, classified to domain by
  `scripts/01_extract_nvd.py`; hand audit 95/97 correct) are resampled with shrinkage to the pooled pool; simulated arm:
  attributes drawn uniformly.
* Twelve controls (ETSI EN 303 645, NIST IR 8259A, NIST CSF 2.0). Effect of control k on vulnerability v depends on the
  weakness class (from CWE) and the attack vector. IDS effect = detection rate x response probability (0.5); detection
  rates are measured on CIC IoT-DIAD 2024 in the real arm (`scripts/03_cic_ids_detection.py`), 0.9 in the simulated arm.
* Existing controls: prevalence 0.3; in the real arm, transport encryption is present when the device's measured
  encrypted share is >= 0.9 (`scripts/02_cic_transfer_protection.py`). Existing controls are sunk and never removed.
* Objectives (fleet means, maximised): S, P, T, CS (Eqs. 1-14 in `cmof/model.py`). Trust components are technical
  trustworthiness proxies, not consumer perceptions. CS is requirement coverage against a published traceability matrix
  (GDPR 8, POPIA 7, NIST CSF 2.0 7 requirements), not a legal determination.
* Constraints: per-device latency and throughput caps (by domain); fleet budget B; fleet CS >= 0.6.
* Budget: B = fraction x cost of adding every missing control on every device. Reference fraction 0.5.

## 4. Optimiser
NSGA-II (pymoo 0.6.2), population 200, 300 generations, device-level integer encoding over each device's menu of
feasible configurations that are not dominated in (cost, S, P, T, CS contribution); uniform crossover p = 0.9; mutation
per device with probability 1/N (random option or step of +-1..3); repair to budget by downgrading the device with the
smallest composite loss per unit cost saved. Final front: feasible non-dominated members. Representative solution: the
knee (closest to the ideal point after min-max normalisation over the front).
Design choice made during piloting on one instance (seed 7, not part of any experiment): a bit-string encoding reached
the exact weighted optimum within 2.3% and a device-level encoding within 0.2% on that instance; the device-level
encoding was adopted. Both are compared in E3.
Exact reference: for 11 weight vectors (das-dennis lattice with 2 partitions, plus equal weights) the weighted-sum
optimum is solved exactly as a multiple-choice knapsack MILP (HiGHS). Gap = (exact - best front value) / exact.

## 5. Baselines (same instance, same budget)
B0 as-is; B1 ETSI EN 303 645 checklist order; B2 greedy security per cost; B3 exact compliance-only; B4 random
feasible additions (mean of 200 draws); B5 exact equal-weight scalarisation.

## 6. Experiments
* E1 main: both arms, R = 50 replications, reference budget.
* E2 budget sweep: both arms, R = 20, budget fractions 0.2, 0.35, 0.5, 0.65, 0.8, 1.0.
* E3 algorithms: real arm, R = 20: NSGA-II, NSGA-III, MOEA/D (penalty for the compliance threshold), bit-string NSGA-II.
* E4 sensitivity: real arm, R = 20, one change at a time: lambda 2, 10; beta 0.05, 0.20; rho 0.25, 0.75; all
  effectiveness x0.7, x1.3; latency caps x0.5, x1.5; existing-control prevalence 0.1, 0.5; three random cost
  perturbations (each control's cost x U(0.5, 1.5), generator seed 99).
* E5 ablation: real arm, R = 20, each real input replaced by its simulated counterpart (CVE pool, IDS detection, transfer
  protection baseline), chipset-vendor CVEs excluded, KEV multiplier off.
Seeds: instance seed = 20261123 + 1000 x rep (+500 simulated arm); optimiser seed = instance seed + 7.

## 7. Outcomes and analysis
Primary (E1, each arm): knee vs each baseline B1-B5 on S, P, T and CS: paired differences over replications; mean and
95% percentile-bootstrap CI (10,000 resamples); two-sided Wilcoxon signed-rank; Holm correction over the four
objectives within each baseline; matched-pairs rank-biserial effect size.
Reading rule (fixed now): the knee is said to *outperform* a baseline only if it is significantly better on at least one
objective and not significantly worse on any; if it is better on some and worse on others the result is reported as a
*trade-off*, with the direction of each objective. No overall "superiority" claim is made otherwise.
Secondary: share of replications in which each baseline is dominated by the NSGA-II front; hypervolume relative to the
as-is point; exact gaps per weight vector; compliance-threshold attainment; per-domain scores and control adoption of
the knee; real vs simulated arm (Mann-Whitney U on the knee's gain over as-is, and on control adoption shares).
Adequacy of R: 95% CI half-width of each knee objective below 0.005 in E1; reported.
E2-E5 are descriptive: medians and IQRs; for E4/E5 the change of the knee's objectives relative to E1-reference
settings (same replications 0-19) and whether each E1 comparison verdict changes.

## 8. Reporting commitments
Every number in the manuscript is generated from `results/` by `make_outputs.py`. All parameters, code, processed data
and the audit sample are released. Limitations to state: assumed effectiveness/cost/latency values; CVE counts are not
exposure rates; healthcare pool is small and clinical; CIC data cover smart-home devices only and show capture-session
shift; packet-level detection is a proxy; compliance coverage needs expert legal validation; trust proxies are not
consumer perceptions.

## Post-freeze log
- 2026-11-23, after E1: `make_outputs.py` (analysis, not a frozen file) read a `cost` field that the random baseline B4 does
  not store (B4 is a mean over 200 draws); fixed to treat it as missing. No result changed.
- 2026-11-23: no frozen file (model, optimiser, experiment runner, parameters, data) was changed after the freeze; verify with
  `sha256sum -c` against `FREEZE.sha256` (first line is the timestamp).
- Analysis choices made after seeing results, all descriptive and labelled as such in the manuscript: the per-arm control
  adoption comparison quoted in the Discussion, and the ablation gain figures quoted in Section 5.6.
