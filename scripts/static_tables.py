"""Tables generated from params.json (no results needed): controls, traceability matrix, parameter provenance."""
import json, os
import pandas as pd

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
P = json.load(open(os.path.join(ROOT, "params.json")))
TAB = os.path.join(ROOT, "outputs", "tables"); os.makedirs(TAB, exist_ok=True)

# controls
eff = P["effectiveness"]
def eff_txt(k):
    e = eff.get(k, {})
    if k == "k3": return "0.70 on every weakness class"
    if k == "k10": return "0.10 on every class (faster response)"
    if k == "k6": return "0.50 network-, 0.70 adjacent-vector vulnerabilities"
    if k == "k7": return "measured detection rate x 0.5 response (network/adjacent)"
    if k == "k8": return "0.50 injection, memory, access, other; 0.30 DoS (network/adjacent)"
    if k == "k11": return "0.60 reduction of availability loss"
    if k == "k9": return "collection exposure x (1 - 0.70)"
    if k == "k12": return "no direct technical effect (transparency)"
    return "; ".join(f"{v:.2f} {c.lower()}" for c, v in e.items())
rows = [dict(id=c["id"], control=c["name"], source=c["ref"], cost_zar=c["cost"], latency_ms=c["lat"], throughput_loss=c["thr"],
             effect=eff_txt(c["id"])) for c in P["controls"]["list"]]
pd.DataFrame(rows).to_csv(os.path.join(TAB, "T_controls.csv"), index=False)

# traceability matrix
rows = []
for fw in ("GDPR", "POPIA", "NIST"):
    for r in P["compliance"][fw]:
        dom = ", ".join(r.get("domains", [])) or ("all except industrial" if fw != "NIST" else "all")
        rows.append(dict(framework={"NIST": "NIST CSF 2.0"}.get(fw, fw), id=r["id"], requirement=r["ref"],
                         control_rule=r["rule"].replace("&", " AND ").replace("|", " OR "), applies_to=dom))
pd.DataFrame(rows).to_csv(os.path.join(TAB, "T_traceability.csv"), index=False)

# parameter provenance
v, pr, cn = P["vulnerabilities"], P["privacy"], P["constraints"]
NAMES = {"smart_home": "smart home", "healthcare": "healthcare", "wearable": "wearable", "vehicle": "vehicle", "industrial": "industrial"}
def dd(d, fmt="{}"):
    return ", ".join(f"{NAMES[k]} {fmt.format(v)}" for k, v in d.items())
def ll(x):
    return " and ".join(str(v) for v in x)
rows = [
 ("Device vulnerability records (CVSS C/I/A, attack vector, exploitability, CWE)", "NVD 2021-2025, 1,372 consumer-IoT records", "Measured"),
 ("Actively exploited flag", "CISA KEV catalogue (version 2026.11.20)", "Measured"),
 ("Baseline transfer protection (encrypted share of traffic)", "CIC IoT-DIAD 2024 benign captures, 47 devices", "Measured"),
 ("IDS detection rate by attack class", "CIC IoT-DIAD 2024, 27 attack sub-categories", "Measured"),
 ("CVSS impact coefficients (High 0.56, Low 0.22)", "FIRST CVSS v3.1 specification", "Standard"),
 ("Control catalogue and requirement wording", "ETSI EN 303 645; NIST IR 8259A; NIST CSF 2.0; GDPR; POPIA", "Standard"),
 (f"Open vulnerabilities per device: Poisson mean {v['lambda_per_device']} (tested {ll(v['lambda_sensitivity'])})", "-", "Assumed"),
 (f"Annual exploitation propensity β = {v['beta_exploit']:.2f} (tested {ll(v['beta_sensitivity'])}); KEV multiplier κ = {v['kev_multiplier']}", "-", "Assumed"),
 (f"IDS response probability {P['ids']['rho_response']} (tested {ll(P['ids']['rho_sensitivity'])})", "-", "Assumed"),
 ("Control effectiveness values (Table 3; all scaled x0.7 and x1.3 in sensitivity)", "-", "Assumed"),
 ("Control cost, latency and throughput (Table 3; costs perturbed U(0.5,1.5))", "-", "Assumed"),
 (f"Existing-control prevalence {P['existing_controls']['prevalence']} (tested {ll(P['existing_controls']['prevalence_sensitivity'])})", "measured for transport encryption in the real arm", "Assumed"),
 ("Collection and storage exposure, trust-proxy forms", "-", "Assumed"),
 (f"Latency caps (ms): {dd(cn['latency_max_ms'])} (x0.5 and x1.5 tested); throughput floors: {dd(cn['throughput_min'], '{:.2f}')}", "-", "Assumed"),
 (f"Budget fractions {', '.join(str(b) for b in cn['budget_fractions'])} (reference {cn['budget_reference']}); compliance threshold {cn['compliance_threshold']}", "-", "Assumed"),
 ("Simulated arm: impacts, attack vector, weakness class uniform; exploitability U(0.5,3.9); KEV prob. 0.02; transfer protection U(0.4,0.8); IDS 0.9", "-", "Assumed (simulated arm only)"),
]
pd.DataFrame(rows, columns=["parameter", "source", "provenance"]).to_csv(os.path.join(TAB, "T_parameters.csv"), index=False)
print("ok")
