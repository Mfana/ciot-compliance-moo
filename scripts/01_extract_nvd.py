"""Extract consumer-IoT CVE records from the NVD JSON mirror (fkie-cad/nvd-json-data-feeds).

Usage: python3 01_extract_nvd.py <nvd_root> <kev.json> <out.csv>

A CVE is assigned to a device domain (whole-token match) when any affected CPE's product (or vendor:product) matches that domain's
pre-specified pattern below. Patterns are applied to CPE product strings only (not free-text descriptions), so the
rule is mechanical and auditable. CVEs matching more than one domain are kept once per domain and flagged.
Window: CVEs published 2021-01-01 to 2025-12-31.
"""
import json, os, re, sys, csv, glob
from multiprocessing import Pool

DOMAIN_PATTERNS = {
    "smart_home": r"(ip_?cam|camera|webcam|doorbell|baby_?monitor|nvr|dvr|smart_?plug|wi-?fi_?plug|smart_?bulb|"
                  r"smart_?light|light_?bulb|thermostat|smart_?lock|door_?lock|smart_?speaker|echo_(dot|show)|"
                  r"nest_|home_?hub|smart_?hub|smart_?home|robot_?vacuum|vacuum_?cleaner|smart_?switch|"
                  r"garage_?door|smoke_?detector|smart_?tv|smart_?fridge|smart_?doorbell|security_?camera)",
    "healthcare": r"(insulin|glucose|cgm|pacemaker|cardiac|defibrillator|infusion|patient_?monitor|"
                  r"blood_?pressure|oximeter|hearing_?aid|ventilator|nebuli[sz]er|medical_?device|"
                  r"health_?monitor|ecg|telehealth|dialysis)",
    "wearable":   r"(smart_?watch|smartwatch|fitness_?(band|tracker)|activity_?tracker|wearable|fitbit|"
                  r"amazfit|mi_?band|galaxy_?watch|apple_?watch|smart_?band|smart_?glasses|smart_?ring|"
                  r"earbuds|watch_?firmware|kids_?watch)",
    "vehicle":    r"(vehicle|automotive|infotainment|telematics|head_?unit|car_?kit|carplay|android_?auto|"
                  r"ev_?charg|charging_?station|wallbox|charge_?point|tbox|t-box|ivi_|in-vehicle|obd|"
                  r"dashcam|dash_?cam|key_?fob|model_[3sxy])",
    "industrial": r"(plc|scada|hmi|rtu|simatic|modicon|controllogix|compactlogix|micrologix|"
                  r"industrial_?(router|switch|gateway|controller)|ics_|dcs_|historian|"
                  r"ecostruxure|wincc|factorytalk|melsec|tia_portal|codesys|iiot)",
}
PAT = {d: re.compile(r"(?<![a-z])" + p + r"(?![a-z])", re.I) for d, p in DOMAIN_PATTERNS.items()}
# whole-token matching: a pattern may not be preceded or followed by a letter (digits, _ and - are boundaries)
# Exclusions fixed after two audit passes (logged in PROTOCOL.md): business web applications that only
# contain the word "vehicle", and "model_N" products from vendors other than Tesla.
EXCLUDE = {"vehicle": re.compile(r"(management|shop|parking|rental|booking|dealer|inventory|billing|triconex|sinumerik|qms)", re.I)}
VENDOR_EXCLUDE = {"vehicle": {"ovarro"}}
VENDOR_ONLY = {"vehicle": (re.compile(r"^model_[3sxy]", re.I), {"tesla"})}
CHIPSET_VENDORS = {"qualcomm", "mediatek", "unisoc", "broadcom", "realtek", "nxp", "intel", "arm"}
START, END = "2021-01-01", "2025-12-31T23:59:59"


def cvss(m):
    """Primary NVD CVSS v3.1/v3.0 if present, else first secondary."""
    for key in ("cvssMetricV31", "cvssMetricV30"):
        arr = m.get(key) or []
        prim = [x for x in arr if x.get("type") == "Primary"]
        pick = (prim or arr)
        if pick:
            d = pick[0]["cvssData"]
            return dict(cvss_src="primary" if prim else "secondary", base=d["baseScore"], av=d["attackVector"],
                        ac=d["attackComplexity"], pr=d["privilegesRequired"], ui=d["userInteraction"],
                        c=d["confidentialityImpact"], i=d["integrityImpact"], a=d["availabilityImpact"],
                        expl=pick[0].get("exploitabilityScore"))
    return None


def cpes(rec):
    out = set()
    for conf in rec.get("configurations", []) or []:
        for node in conf.get("nodes", []):
            for cm in node.get("cpeMatch", []):
                if cm.get("vulnerable"):
                    out.add(cm["criteria"])
    for aff in rec.get("affected", []) or []:
        for ad in aff.get("affectedData", []):
            for c in ad.get("cpes", []) or []:
                out.add(c)
    return out


def handle(path):
    try:
        rec = json.load(open(path))
    except Exception:
        return []
    pub = rec.get("published", "")
    if not (START <= pub <= END) or rec.get("vulnStatus") == "Rejected":
        return []
    cs = cpes(rec)
    hits = {}
    for c in cs:
        parts = c.split(":")
        if len(parts) < 6:
            continue
        part, vendor, product = parts[2], parts[3], parts[4]
        for d, p in PAT.items():
            if p.search(product):
                if d in EXCLUDE and EXCLUDE[d].search(product):
                    continue
                if vendor in VENDOR_EXCLUDE.get(d, ()):
                    continue
                if d in VENDOR_ONLY and VENDOR_ONLY[d][0].search(product) and vendor not in VENDOR_ONLY[d][1]:
                    continue
                hits.setdefault(d, (part, vendor, product))
    if not hits:
        return []
    m = cvss(rec.get("metrics", {}) or {})
    cwes = sorted({x["value"] for w in rec.get("weaknesses", []) or [] for x in w["description"]
                   if x["value"].startswith("CWE-")})
    desc = next((x["value"] for x in rec.get("descriptions", []) if x["lang"] == "en"), "")
    rows = []
    for d, (part, vendor, product) in hits.items():
        rows.append(dict(cve=rec["id"], published=pub[:10], domain=d, multi=len(hits) > 1, part=part, chipset=vendor in CHIPSET_VENDORS,
                         vendor=vendor, product=product, cwes="|".join(cwes),
                         **(m or dict(cvss_src="none", base=None, av=None, ac=None, pr=None, ui=None,
                                      c=None, i=None, a=None, expl=None)),
                         desc=desc[:300].replace("\n", " ")))
    return rows


if __name__ == "__main__":
    root, kevp, outp = sys.argv[1:4]
    kev = {v["cveID"] for v in json.load(open(kevp))["vulnerabilities"]}
    files = [f for y in range(2021, 2026) for f in glob.glob(os.path.join(root, f"CVE-{y}", "*", "*.json"))]
    with Pool(2) as pool:
        rows = [r for rs in pool.imap_unordered(handle, files, chunksize=500) for r in rs]
    for r in rows:
        r["kev"] = r["cve"] in kev
    rows.sort(key=lambda r: (r["domain"], r["cve"]))
    with open(outp, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader(); w.writerows(rows)
    print("scanned", len(files), "records; kept", len(rows), "domain rows")
