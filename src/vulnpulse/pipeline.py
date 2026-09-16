from pathlib import Path

from .nessus import NessusClient
from .parser import parse_vulnerabilities
from .risk import prioritize_findings


def run_pipeline():
    """Execute the complete VulnPulse pipeline."""

    print("=" * 70)
    print("VulnPulse - Nessus Vulnerability Management Pipeline")
    print("=" * 70)

    client = NessusClient()

    print("\n[+] Configuration loaded")
    print(f"[+] Nessus URL : {client.base_url}")
    print(f"[+] Scan       : {client.scan_name}")

    print("\n[+] Connecting to Nessus...")

    scans = client.get_scans()

    print("[+] Nessus API connection successful")
    print(f"[+] Available scans: {len(scans)}")

    scan = client.find_scan()

    scan_id = scan["id"]

    print(f"[+] Scan found : {scan['name']}")
    print(f"[+] Scan ID    : {scan_id}")
    print(
        f"[+] Status     : "
        f"{scan.get('status', 'unknown')}"
    )

    print("\n[+] Downloading scan results...")

    scan_results = client.download_scan(scan_id)

    print("[+] Scan results downloaded")

    raw_path = Path("Scans/nessus_scan.json")

    client.save_raw_scan(
        scan_results,
        raw_path
    )

    print(f"[+] Raw JSON saved: {raw_path}")

    df = parse_vulnerabilities(
        scan_results
    )

    print(
        f"[+] API vulnerability records: "
        f"{len(df)}"
    )

    df = prioritize_findings(
        df,
        asset_criticality=3
    )

    output_path = Path(
        "Outputs/prioritized_findings.csv"
    )

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    df.to_csv(
        output_path,
        index=False
    )

    print(
        f"[+] Prioritized CSV saved: "
        f"{output_path}"
    )

    print("\n" + "=" * 70)
    print("VULNERABILITY SUMMARY")
    print("=" * 70)

    summary = df["Severity"].value_counts()

    for severity in [
        "Critical",
        "High",
        "Medium",
        "Low",
        "Info"
    ]:
        print(
            f"{severity:<10}: "
            f"{summary.get(severity, 0)}"
        )

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

    print("\n" + "=" * 70)
    print("VulnPulse pipeline completed successfully.")
    print("=" * 70)


if __name__ == "__main__":
    run_pipeline()