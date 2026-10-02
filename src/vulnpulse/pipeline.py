from pathlib import Path

from .nessus import NessusClient
from .parser import parse_vulnerabilities
from .risk import prioritize_findings
from .report import generate_report


# ----------------------------------------------------------------------
# Lab asset inventory
#
# These hostnames, platforms and criticality values are defined for the
# VulnPulse demonstration lab.
# ----------------------------------------------------------------------

ASSET_INVENTORY = {
    "192.168.84.128": {
        "hostname": "m2-legacy",
        "platform": "Linux (Ubuntu 8.04)",
        "criticality": 3,
    },
    "192.168.84.129": {
        "hostname": "win10-nova",
        "platform": "Windows 10",
        "criticality": 2,
    },
    "192.168.84.130": {
        "hostname": "vple-web",
        "platform": "Linux (Ubuntu 14.04)",
        "criticality": 1,
    },
}


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
    # Build host-specific vulnerability dataset.
    #
    # The scan-level vulnerability list can contain aggregate records.
    # We therefore retrieve vulnerability records separately for every
    # host to preserve correct host attribution.
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

            # Preserve the Nessus host association.
            vulnerability["host_id"] = host_id

            host_vulnerabilities.append(
                vulnerability
            )

    # Replace the aggregate vulnerability list with the
    # host-specific records collected above.
    scan_results["vulnerabilities"] = (
        host_vulnerabilities
    )

    print(
        f"[+] Host-specific vulnerability records: "
        f"{len(host_vulnerabilities)}"
    )

    # ------------------------------------------------------------------
    # Save the local raw scan data.
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
    # Build inventory mappings.
    # ------------------------------------------------------------------

    hostname_inventory = {
        ip: asset["hostname"]
        for ip, asset in ASSET_INVENTORY.items()
    }

    platform_inventory = {
        ip: asset["platform"]
        for ip, asset in ASSET_INVENTORY.items()
    }

    asset_criticality = {
        ip: asset["criticality"]
        for ip, asset in ASSET_INVENTORY.items()
    }

    # ------------------------------------------------------------------
    # Parse and normalize vulnerability data.
    # ------------------------------------------------------------------

    df = parse_vulnerabilities(
        scan_results,
        asset_inventory=hostname_inventory
    )

    # Add platform information from the lab inventory.
    df["Platform"] = (
        df["IP Address"]
        .map(platform_inventory)
        .fillna("Unknown")
    )

    print(
        f"[+] API vulnerability records: "
        f"{len(df)}"
    )

    # ------------------------------------------------------------------
    # Calculate priority using asset-specific criticality.
    # ------------------------------------------------------------------

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
            [
                "Hostname",
                "IP Address",
                "Platform",
                "Asset Criticality",
            ]
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
            "Hostname",
            "IP Address",
            "Platform",
            "Severity",
            "CVSS",
            "VPR",
            "EPSS",
            "Vulnerability",
            "Asset Criticality",
            "Priority Score",
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