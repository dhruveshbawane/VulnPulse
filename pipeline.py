import os
import json
import requests
import urllib3
import pandas as pd

from dotenv import load_dotenv


# ============================================================
# VULNPULSE
# Automated Nessus Vulnerability Collection & Prioritization
# ============================================================

print("=" * 70)
print("VulnPulse - Nessus Vulnerability Management Pipeline")
print("=" * 70)


# ============================================================
# 1. LOAD CONFIGURATION
# ============================================================

load_dotenv()

NESSUS_URL = os.getenv(
    "NESSUS_URL",
    "https://localhost:8834"
)

ACCESS_KEY = os.getenv("NESSUS_ACCESS_KEY")
SECRET_KEY = os.getenv("NESSUS_SECRET_KEY")

SCAN_NAME = os.getenv(
    "NESSUS_SCAN_NAME",
    "Metasploitable2 baseline"
)


if not ACCESS_KEY or not SECRET_KEY:
    raise RuntimeError(
        "Nessus API keys are missing. "
        "Check your .env file."
    )


print("\n[+] Configuration loaded")
print(f"[+] Nessus URL : {NESSUS_URL}")
print(f"[+] Scan       : {SCAN_NAME}")


# ============================================================
# 2. CREATE NESSUS API SESSION
# ============================================================

headers = {
    "X-ApiKeys": (
        f"accessKey={ACCESS_KEY}; "
        f"secretKey={SECRET_KEY}"
    ),
    "Accept": "application/json"
}

session = requests.Session()
session.headers.update(headers)

# Nessus uses a self-signed certificate on localhost.
session.verify = False

urllib3.disable_warnings(
    urllib3.exceptions.InsecureRequestWarning
)


# ============================================================
# 3. CONNECT TO NESSUS
# ============================================================

print("\n[+] Connecting to Nessus...")

response = session.get(
    f"{NESSUS_URL}/scans",
    timeout=30
)

response.raise_for_status()

scan_list = response.json()

print("[+] Nessus API connection successful")


# ============================================================
# 4. FIND THE REQUESTED SCAN
# ============================================================

scans = scan_list.get("scans", [])

print(f"[+] Available scans: {len(scans)}")


matching_scans = [
    scan
    for scan in scans
    if scan.get("name") == SCAN_NAME
]


if not matching_scans:
    raise RuntimeError(
        f'Could not find scan "{SCAN_NAME}"'
    )


# Use the latest matching scan
scan = matching_scans[-1]

scan_id = scan["id"]

print(f"[+] Scan found : {scan['name']}")
print(f"[+] Scan ID    : {scan_id}")
print(f"[+] Status     : {scan.get('status', 'unknown')}")


# ============================================================
# 5. DOWNLOAD COMPLETE SCAN RESULTS
# ============================================================

print("\n[+] Downloading scan results...")

response = session.get(
    f"{NESSUS_URL}/scans/{scan_id}",
    timeout=120
)

response.raise_for_status()

scan_results = response.json()

print("[+] Scan results downloaded")


# ============================================================
# 6. SAVE RAW NESSUS JSON
# ============================================================

os.makedirs("Scans", exist_ok=True)

json_path = "Scans/nessus_scan.json"

with open(
    json_path,
    "w",
    encoding="utf-8"
) as file:

    json.dump(
        scan_results,
        file,
        indent=2
    )

print(f"[+] Raw JSON saved: {json_path}")


# ============================================================
# 7. GET HOST INFORMATION
# ============================================================

hosts = scan_results.get("hosts", [])

if hosts:

    host = hosts[0]

    hostname = host.get(
        "hostname",
        "Unknown"
    )

else:

    hostname = "Unknown"


print(f"[+] Target host: {hostname}")


# ============================================================
# 8. GET VULNERABILITY RECORDS
# ============================================================

vulnerabilities = scan_results.get(
    "vulnerabilities",
    []
)

print(
    f"[+] API vulnerability records: "
    f"{len(vulnerabilities)}"
)


# ============================================================
# 9. SEVERITY MAPPING
# ============================================================

severity_mapping = {
    4: "Critical",
    3: "High",
    2: "Medium",
    1: "Low",
    0: "Info"
}


# ============================================================
# 10. NORMALIZE VULNERABILITIES
# ============================================================

rows = []


for vulnerability in vulnerabilities:

    severity_number = vulnerability.get(
        "severity"
    )

    severity_name = severity_mapping.get(
        severity_number,
        "Unknown"
    )

    cvss = vulnerability.get(
        "score"
    )

    vpr = vulnerability.get(
        "vpr_score"
    )

    epss = vulnerability.get(
        "epss_score"
    )

    # Detect whether Nessus is using a fallback
    # CVSS v2 score.
    fallback_score = vulnerability.get(
        "isFallBackScore",
        False
    )

    if fallback_score:

        cvss_version = "CVSS v2"

    else:

        cvss_version = "CVSS"


    rows.append({

        "Host": hostname,

        "Plugin ID":
            vulnerability.get("plugin_id"),

        "Vulnerability":
            vulnerability.get("plugin_name"),

        "Severity":
            severity_name,

        "Severity Score":
            severity_number,

        "CVSS":
            cvss,

        "CVSS Version":
            cvss_version,

        "VPR":
            vpr,

        "EPSS":
            epss,

        "Plugin Family":
            vulnerability.get("plugin_family"),

        "Count":
            vulnerability.get("count")

    })


# ============================================================
# 11. CREATE DATAFRAME
# ============================================================

df = pd.DataFrame(rows)


if df.empty:

    raise RuntimeError(
        "No vulnerability records were returned."
    )


# ============================================================
# 12. CLEAN NUMERIC COLUMNS
# ============================================================

df["CVSS"] = pd.to_numeric(
    df["CVSS"],
    errors="coerce"
)

df["VPR"] = pd.to_numeric(
    df["VPR"],
    errors="coerce"
)

df["EPSS"] = pd.to_numeric(
    df["EPSS"],
    errors="coerce"
)


# ============================================================
# 13. ASSET CRITICALITY
# ============================================================

# Metasploitable2 is deliberately vulnerable and
# is being treated as a high-priority lab asset.

asset_criticality = 3

df["Asset Criticality"] = asset_criticality


# ============================================================
# 14. CALCULATE BASE PRIORITY
# ============================================================

df["Priority Score"] = (
    df["Severity Score"] *
    df["Asset Criticality"]
)


# ============================================================
# 15. SORT FINDINGS
# ============================================================

df = df.sort_values(
    by=[
        "Priority Score",
        "CVSS",
        "VPR",
        "EPSS"
    ],
    ascending=[
        False,
        False,
        False,
        False
    ],
    na_position="last"
)


# ============================================================
# 16. SAVE PRIORITIZED CSV
# ============================================================

os.makedirs(
    "Outputs",
    exist_ok=True
)

csv_path = (
    "Outputs/"
    "prioritized_findings.csv"
)

df.to_csv(
    csv_path,
    index=False
)


print(
    f"[+] Prioritized CSV saved: "
    f"{csv_path}"
)


# ============================================================
# 17. DISPLAY SUMMARY
# ============================================================

print("\n" + "=" * 70)
print("VULNERABILITY SUMMARY")
print("=" * 70)

summary = (
    df["Severity"]
    .value_counts()
)

for severity in [
    "Critical",
    "High",
    "Medium",
    "Low",
    "Info"
]:

    count = summary.get(
        severity,
        0
    )

    print(
        f"{severity:<10}: {count}"
    )


# ============================================================
# 18. DISPLAY TOP FINDINGS
# ============================================================

print("\n" + "=" * 70)
print("TOP PRIORITY FINDINGS")
print("=" * 70)

top_findings = df[
    [
        "Severity",
        "CVSS",
        "VPR",
        "EPSS",
        "Vulnerability",
        "Priority Score"
    ]
].head(10)


print(
    top_findings.to_string(
        index=False
    )
)


# ============================================================
# 19. COMPLETE
# ============================================================

print("\n" + "=" * 70)
print("VulnPulse pipeline completed successfully.")
print("=" * 70)