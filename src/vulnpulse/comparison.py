from collections import Counter


COMPARISON_COLUMNS = [
    "IP Address",
    "Plugin ID",
]


def _finding_keys(df):
    """
    Build a set of stable finding identities.

    A finding is identified by:
        IP Address + Plugin ID
    """

    keys = set()

    for _, row in df.iterrows():
        ip_address = str(
            row.get("IP Address", "")
        ).strip()

        plugin_id = str(
            row.get("Plugin ID", "")
        ).strip()

        if not ip_address or not plugin_id:
            continue

        keys.add(
            (
                ip_address,
                plugin_id,
            )
        )

    return keys


def _severity_counts(df):
    """Return severity counts in a consistent order."""

    severities = [
        "Critical",
        "High",
        "Medium",
        "Low",
        "Info",
    ]

    counts = Counter(
        df.get(
            "Severity",
            []
        )
    )

    return {
        severity: int(
            counts.get(
                severity,
                0
            )
        )
        for severity in severities
    }


def compare_findings(
    baseline_df,
    comparison_df,
):
    """
    Compare two VulnPulse finding datasets.

    The result describes visibility differences between the
    datasets. It does not treat credentialed-only findings as
    newly introduced vulnerabilities.
    """

    baseline_keys = _finding_keys(
        baseline_df
    )

    comparison_keys = _finding_keys(
        comparison_df
    )

    common_keys = (
        baseline_keys
        & comparison_keys
    )

    baseline_only_keys = (
        baseline_keys
        - comparison_keys
    )

    comparison_only_keys = (
        comparison_keys
        - baseline_keys
    )

    baseline_assets = set(
        baseline_df.get(
            "IP Address",
            []
        ).dropna().astype(str)
    )

    comparison_assets = set(
        comparison_df.get(
            "IP Address",
            []
        ).dropna().astype(str)
    )

    additional_visibility = len(
        comparison_only_keys
    )

    return {
        "baseline_findings": len(
            baseline_df
        ),
        "comparison_findings": len(
            comparison_df
        ),
        "baseline_unique_findings": len(
            baseline_keys
        ),
        "comparison_unique_findings": len(
            comparison_keys
        ),
        "common_findings": len(
            common_keys
        ),
        "baseline_only_findings": len(
            baseline_only_keys
        ),
        "comparison_only_findings": len(
            comparison_only_keys
        ),
        "additional_visibility": additional_visibility,
        "baseline_assets": len(
            baseline_assets
        ),
        "comparison_assets": len(
            comparison_assets
        ),
        "baseline_severity": _severity_counts(
            baseline_df
        ),
        "comparison_severity": _severity_counts(
            comparison_df
        ),
    }