import argparse
import re
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


# ----------------------------------------------------------------------
# Known scan output names.
#
# These keep the two important lab datasets clearly separated.
# ----------------------------------------------------------------------

SCAN_OUTPUT_NAMES = {
    "Metasploitable2 baseline": "baseline_3host",
    "VulnPulse - Windows 10 Credentialed": "windows10_credentialed",
}


def _slugify_scan_name(scan_name):
    """Convert a scan name into a safe filesystem-friendly name."""

    if scan_name in SCAN_OUTPUT_NAMES:
        return SCAN_OUTPUT_NAMES[scan_name]

    slug = scan_name.lower()
    slug = re.sub(r"[^a-z0-9]+", "_", slug)
    slug = slug.strip("_")

    return slug or "scan"


def run_pipeline(scan_name=None):
    """Execute the complete VulnPulse pipeline."""

    print("=" * 70)
    print("VulnPulse - Nessus Vulnerability Management Pipeline")
    print("=" * 70)

    client = NessusClient()

    # ------------------------------------------------------------------
    # Optional command-line scan override.
    #
    # Without --scan, the value from NESSUS_SCAN_NAME in .env is used.
    # ------------------------------------------------------------------

    if scan_name:
        client.scan_name = scan_name

    output_name = _slugify_scan_name(
        client.scan_name
    )

    raw_path = Path(
        "Scans"
    ) / f"{output_name}.json"

    output_directory = Path(
        "Outputs"
    ) / output_name

    output_path = (
        output_directory
        / "prioritized_findings.csv"
    )

    report_path = (
        output_directory
        / "vulnerability_report.html"
    )

    print("\n[+] Configuration loaded")
    print(f"[+] Nessus URL : {client.base_url}")
    print(f"[+] Scan       : {client.scan_name}")
    print(f"[+] Dataset    : {output_name}")

    print("\n[+] Connecting to Nessus...")

    scans = client.get_scans()

    print("[+] Nessus API connection successful")
    print(f"[+] Available scans: {len(scans)}")

    # ------------------------------------------------------------------
    # Locate the requested scan.
    # ------------------------------------------------------------------

    scan = client.find_scan()

    scan_id = scan["id"]

    print(f"[+] Scan found : {scan['name']}")
    print(f"[+] Scan ID    : {scan_id}")
    print(
        f"[+] Status     : "
        f"{scan.get('status', 'unknown')}"
    )

    # ------------------------------------------------------------------
    # Download scan-level data.
    # ------------------------------------------------------------------

    print("\n[+] Downloading scan results...")

    scan_results = client.download_scan(
        scan_id
    )

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
            f"    |- Vulnerability records: "
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
        "Info",
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


def parse_arguments():
    """Parse command-line options."""

    parser = argparse.ArgumentParser(
        description=(
            "Run the VulnPulse Nessus vulnerability "
            "management pipeline."
        )
    )

    parser.add_argument(
        "--scan",
        dest="scan_name",
        help=(
            "Nessus scan name to process. "
            "If omitted, NESSUS_SCAN_NAME from .env is used."
        ),
    )

    return parser.parse_args()


if __name__ == "__main__":
    args = parse_arguments()
    run_pipeline(
        scan_name=args.scan
    )