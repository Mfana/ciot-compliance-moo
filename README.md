# Compliance-aware multi-objective control selection for consumer IoT: IJSP revision package

Code, data and protocol behind the revised manuscript *Enhancing Security, Privacy, Trust, and Regulatory Compliance in
Consumer Internet of Things Ecosystems: A Compliance-Aware Multi-Objective Framework* (IJSP, revision).
Every number, table and figure in the manuscript is generated from `results/` by `make_outputs.py`; nothing is typed by hand.
The manuscript itself is not included; `outputs/` holds the generated tables, figures and numbers it reads.

This package is separate from `ciot-engine` (Papers 1-3). It shares no results, model instance or code with them.

## What the study does
* 100 devices in five domains (smart home, healthcare, wearable, vehicle, industrial IoT), 12 controls (ETSI EN 303 645,
  NIST IR 8259A, NIST CSF 2.0), binary decisions x[i,k].
* Four objectives: security (C, I, A), privacy (CP, SP, TP), trust proxies (TD, TN, TCB), compliance coverage
  (GDPR, POPIA, NIST CSF 2.0 requirement traceability matrix). Constraints: budget, per-device latency and throughput,
  CS >= 0.6.
* NSGA-II with a device-level encoding; every run checked against exact weighted-sum optima (MILP, HiGHS); NSGA-III and
  MOEA/D for comparison; five alternative selection approaches at equal cost.
* Two arms: simulated (all device states from stated ranges) and real-data (NVD 2021-2025, CISA KEV, CIC IoT-DIAD 2024).

## Layout
```
params.json                 every parameter, tagged measured / standard / assumed
PROTOCOL.md, FREEZE.sha256  protocol (with post-freeze log); PROTOCOL_at_freeze.md is the exact frozen text, hash in FREEZE.sha256
cmof/model.py               instance generation (both arms), scoring equations, constraints, per-device enumeration
cmof/opt.py                 NSGA-II/NSGA-III/MOEA-D (device-level and bit-string encodings), exact MILP, baselines
scripts/01_extract_nvd.py   NVD JSON -> consumer-IoT CVE records by domain (data/nvd_ciot.csv)
scripts/02_cic_transfer_protection.py   CIC IoT-DIAD benign traffic -> per-device encrypted share
scripts/03_cic_ids_detection.py         CIC IoT-DIAD -> detection rate by attack class at 1% benign FPR
scripts/static_tables.py, fig_framework.py, fig_workflow.py   tables and figures that need no results
run_experiments.py          E1 main, E2 budget sweep, E3 algorithms, E4 sensitivity, E5 ablation
make_outputs.py             statistics, tables (outputs/tables), figures (outputs/figures), numbers (outputs/numbers.json)
data/                       processed inputs (CVE records, KEV catalogue, CIC measurements, audit sample)
results/                    per-replication results (JSON lines), including per-domain values and control adoption
```

## Reproduce
```
pip install -r requirements.txt
python3 run_experiments.py main && python3 run_experiments.py sweep && python3 run_experiments.py algos \
  && python3 run_experiments.py sensitivity && python3 run_experiments.py ablation      # about 2.5 h on 2 cores
python3 make_outputs.py
```
The processed inputs in `data/` are enough to rerun every experiment. To rebuild them from source:
* NVD: `git clone --filter=blob:none https://github.com/fkie-cad/nvd-json-data-feeds` (CVE-2021 to CVE-2025), then
  `python3 scripts/01_extract_nvd.py <nvd_root> data/kev.json data/nvd_ciot.csv`.
* CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog (catalogue version 2026.11.20 is in `data/kev.json`).
* CIC IoT-DIAD 2024 (packet-based features, converted to parquet): https://www.unb.ca/cic/datasets/iot-diad-2024.html, then
  scripts 02 and 03. The dataset itself is not redistributed.

## Equation numbering
Comments in `cmof/model.py` number the equations in the order they appear in the code. The manuscript numbers them
(1)-(17) as follows: exploitation probability (1); control mitigation (2); C and I (3); A (4); S (5); CP and SP (6); TP (7);
P (8); TD and TN (9); TCB and T (10); requirement coverage (11); fleet objectives (12); problem (13); budget (14); latency and
throughput (15); compliance threshold and existing controls (16); knee (17).

## Status of the values
All control effectiveness, cost, latency and throughput values are assumptions chosen to be plausible and are varied in
the sensitivity analysis. Compliance coverage is requirement coverage against the authors' traceability matrix, not a legal
determination. Trust components are technical proxies, not measured consumer perceptions.

## Licence
MIT.
