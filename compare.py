import argparse
import json
from pathlib import Path

from src.vulnpulse.comparison import compare_findings
from src.vulnpulse.parser import parse_vulnerabilities


DEFAULT_BASELINE = Path(
    "Scans/baseline_3host.json"
)

DEFAULT_COMPARISON = Path(
    "Scans/windows10_credentialed.json"
)

OUTPUT_PATH = Path(
    "Outputs/comparison/scan_comparison.json"
)


def load_scan_dataframe(scan_path):
    """Load a saved Nessus JSON scan and parse it into a DataFrame."""

    scan_path = Path(scan_path)

    if not scan_path.exists():
        raise FileNotFoundError(
            f"Scan file not found: {scan_path}"
        )

    with scan_path.open(
        "r",
        encoding="utf-8"
    ) as file:
        scan_results = json.load(file)

    return parse_vulnerabilities(
        scan_results
    )


def filter_by_host(df, host_ip=None):
    """Optionally restrict a finding dataset to one asset."""

    if not host_ip:
        return df

    if "IP Address" not in df.columns:
        return df.iloc[0:0].copy()

    return df[
        df["IP Address"].astype(str) == host_ip
    ].copy()


def main():
    """Compare two saved VulnPulse scan datasets."""

    parser = argparse.ArgumentParser(
        description=(
            "Compare two saved VulnPulse Nessus scan datasets."
        )
    )

    parser.add_argument(
        "--baseline",
        default=str(DEFAULT_BASELINE),
        help=(
            "Baseline scan JSON path. "
            "Defaults to Scans/baseline_3host.json."
        ),
    )

    parser.add_argument(
        "--comparison",
        default=str(DEFAULT_COMPARISON),
        help=(
            "Comparison scan JSON path. "
            "Defaults to Scans/windows10_credentialed.json."
        ),
    )

    parser.add_argument(
        "--host",
        help=(
            "Optional IP address to compare on the same asset "
            "across both scans."
        ),
    )

    args = parser.parse_args()

    baseline_path = Path(
        args.baseline
    )

    comparison_path = Path(
        args.comparison
    )

    print("=" * 70)
    print("VulnPulse - Scan Comparison")
    print("=" * 70)

    print(
        f"\n[+] Baseline    : "
        f"{baseline_path}"
    )

    print(
        f"[+] Comparison  : "
        f"{comparison_path}"
    )

    if args.host:
        print(
            f"[+] Host scope  : "
            f"{args.host}"
        )

    print("\n[+] Loading baseline scan...")

    baseline_df = load_scan_dataframe(
        baseline_path
    )

    print(
        f"[+] Baseline findings before filtering: "
        f"{len(baseline_df)}"
    )

    print("\n[+] Loading comparison scan...")

    comparison_df = load_scan_dataframe(
        comparison_path
    )

    print(
        f"[+] Comparison findings before filtering: "
        f"{len(comparison_df)}"
    )

    # --------------------------------------------------------------
    # Restrict both datasets to the same asset when --host is used.
    # This makes the comparison an apples-to-apples comparison.
    # --------------------------------------------------------------

    baseline_df = filter_by_host(
        baseline_df,
        args.host
    )

    comparison_df = filter_by_host(
        comparison_df,
        args.host
    )

    if args.host:
        print(
            f"\n[+] Baseline findings for {args.host}: "
            f"{len(baseline_df)}"
        )

        print(
            f"[+] Comparison findings for {args.host}: "
            f"{len(comparison_df)}"
        )

    result = compare_findings(
        baseline_df,
        comparison_df,
    )

    # --------------------------------------------------------------
    # Console summary
    # --------------------------------------------------------------

    print("\n" + "=" * 70)
    print("SCAN COMPARISON")
    print("=" * 70)

    print(
        f"Baseline findings        : "
        f"{result['baseline_findings']}"
    )

    print(
        f"Comparison findings      : "
        f"{result['comparison_findings']}"
    )

    print(
        f"Common findings          : "
        f"{result['common_findings']}"
    )

    print(
        f"Baseline-only findings   : "
        f"{result['baseline_only_findings']}"
    )

    print(
        f"Comparison-only findings : "
        f"{result['comparison_only_findings']}"
    )

    print(
        f"Additional visibility    : "
        f"{result['additional_visibility']}"
    )

    print("\n" + "-" * 70)
    print("BASELINE SEVERITY")
    print("-" * 70)

    for severity, count in (
        result["baseline_severity"]
        .items()
    ):
        print(
            f"{severity:<10}: {count}"
        )

    print("\n" + "-" * 70)
    print("COMPARISON SEVERITY")
    print("-" * 70)

    for severity, count in (
        result["comparison_severity"]
        .items()
    ):
        print(
            f"{severity:<10}: {count}"
        )

    # --------------------------------------------------------------
    # Save comparison JSON
    # --------------------------------------------------------------

    OUTPUT_PATH.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    OUTPUT_PATH.write_text(
        json.dumps(
            result,
            indent=2
        ),
        encoding="utf-8"
    )

    print(
        f"\n[+] Comparison JSON saved: "
        f"{OUTPUT_PATH}"
    )

    print("\n" + "=" * 70)
    print("Scan comparison completed successfully.")
    print("=" * 70)


if __name__ == "__main__":
    main()