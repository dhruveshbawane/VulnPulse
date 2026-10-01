from pathlib import Path

from .nessus import NessusClient
from .parser import parse_vulnerabilities
from .risk import prioritize_findings
from .report import generate_report


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

    # ------------------------------------------------------------------
    # Retrieve vulnerability records separately for each scanned host.
    # This avoids incorrectly assigning one host's findings to another.
    # ------------------------------------------------------------------

    host_vulnerabilities = []

    hosts = scan_results.get(
        "hosts",
        []
    )

    print(
        f"[+] Hosts discovered in scan: "
        f"{len(hosts)}"
    )

    for host in hosts:
        host_id = host.get("host_id")

        hostname = host.get(
            "hostname",
            "Unknown"
        )

        if host_id is None:
            print(
                f"[!] Skipping host without host_id: "
                f"{hostname}"
            )
            continue

        print(
            f"[+] Downloading host details: "
            f"{hostname} (ID {host_id})"
        )

        host_details = client.get_host_details(
            scan_id,
            host_id
        )

        vulnerabilities = host_details.get(
            "vulnerabilities",
            []
        )

        print(
            f"    └─ Vulnerability records: "
            f"{len(vulnerabilities)}"
        )

        for vulnerability in vulnerabilities:
            vulnerability = vulnerability.copy()

            # Preserve the Nessus host association so the parser
            # can map each record to the correct IP address.
            vulnerability["host_id"] = host_id

            host_vulnerabilities.append(
                vulnerability
            )

    # Replace the aggregate vulnerability list with the
    # host-specific records.
    scan_results["vulnerabilities"] = (
        host_vulnerabilities
    )

    print(
        f"[+] Host-specific vulnerability records: "
        f"{len(host_vulnerabilities)}"
    )

    # ------------------------------------------------------------------
    # Save the raw scan locally.
    # ------------------------------------------------------------------

    raw_path = Path(
        "Scans/nessus_scan.json"
    )

    client.save_raw_scan(
        scan_results,
        raw_path
    )

    print(
        f"[+] Raw JSON saved: "
        f"{raw_path}"
    )

    # ------------------------------------------------------------------
    # Parse vulnerability data.
    # ------------------------------------------------------------------

    df = parse_vulnerabilities(
        scan_results
    )

    print(
        f"[+] API vulnerability records: "
        f"{len(df)}"
    )

    # ------------------------------------------------------------------
    # Define lab asset criticality.
    #
    # These values are for the demonstration lab and are not
    # measurements of real production business importance.
    # ------------------------------------------------------------------

    asset_criticality = {
        "192.168.84.128": 3,  # Metasploitable2
        "192.168.84.129": 2,  # Windows 10
        "192.168.84.130": 1,  # VPLE
    }

    df = prioritize_findings(
        df,
        asset_criticality=asset_criticality
    )

    # ------------------------------------------------------------------
    # Save prioritized CSV.
    # ------------------------------------------------------------------

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

    # ------------------------------------------------------------------
    # Generate HTML report.
    # ------------------------------------------------------------------

    report_path = Path(
        "Outputs/vulnerability_report.html"
    )

    generate_report(
        df,
        report_path
    )

    print(
        f"[+] HTML report saved: "
        f"{report_path}"
    )

    # ------------------------------------------------------------------
    # Vulnerability summary.
    # ------------------------------------------------------------------

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

    # ------------------------------------------------------------------
    # Host summary.
    # ------------------------------------------------------------------

    print("\n" + "=" * 70)
    print("HOST SUMMARY")
    print("=" * 70)

    host_summary = (
        df.groupby(
            ["IP Address", "Asset Criticality"]
        )
        .size()
        .reset_index(
            name="Findings"
        )
    )

    print(
        host_summary.to_string(
            index=False
        )
    )

    # ------------------------------------------------------------------
    # Top priority findings.
    # ------------------------------------------------------------------

    print("\n" + "=" * 70)
    print("TOP PRIORITY FINDINGS")
    print("=" * 70)

    top_findings = df[
        [
            "IP Address",
            "Severity",
            "CVSS",
            "VPR",
            "EPSS",
            "Vulnerability",
            "Asset Criticality",
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