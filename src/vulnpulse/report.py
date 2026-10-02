from pathlib import Path

from jinja2 import Environment, FileSystemLoader


REPORT_DEFAULTS = {
    "Hostname": "Unknown",
    "IP Address": "Unknown",
    "Platform": "Unknown",
    "Plugin ID": "N/A",
    "Vulnerability": "Unknown",
    "Severity": "Info",
    "Severity Score": 0,
    "CVSS": "N/A",
    "CVSS Version": "N/A",
    "VPR": "N/A",
    "EPSS": "N/A",
    "Plugin Family": "N/A",
    "Description": "N/A",
    "Solution": "N/A",
    "CVEs": "N/A",
    "CWE": "N/A",
    "Port": "N/A",
    "Protocol": "N/A",
    "Exploit Available": "N/A",
    "Exploited By Malware": "N/A",
    "CISA Known Exploited": "N/A",
    "Exploit Maturity": "N/A",
    "Count": 0,
    "Asset Criticality": 1,
    "Priority Score": 0,
}


def _prepare_report_data(df):
    """
    Prepare the vulnerability DataFrame for Jinja2 report rendering.

    Adds backward-compatible Hostname/IP columns when older
    datasets only contain a single Host column and fills missing
    report fields with safe defaults.
    """

    report_data = df.copy()

    # ----------------------------------------------------------
    # Backward compatibility
    # ----------------------------------------------------------

    if "Host" in report_data.columns:

        if "Hostname" not in report_data.columns:
            report_data["Hostname"] = report_data["Host"]

        if "IP Address" not in report_data.columns:
            report_data["IP Address"] = report_data["Host"]

    # ----------------------------------------------------------
    # Ensure all report fields exist
    # ----------------------------------------------------------

    for column, default in REPORT_DEFAULTS.items():

        if column not in report_data.columns:
            report_data[column] = default

    # ----------------------------------------------------------
    # Clean missing values
    # ----------------------------------------------------------

    report_data = report_data.fillna("N/A")

    report_data = report_data.replace(
        {
            "nan": "N/A",
            "NaN": "N/A",
            "None": "N/A",
            "null": "N/A",
        }
    )

    return report_data


def _prepare_comparison_data(comparison_result=None):
    """
    Prepare optional scan comparison data for the report template.

    The comparison module returns a dictionary containing finding
    counts, asset counts, and severity distributions. When no
    comparison is available, return a disabled/default structure
    so existing report generation continues to work.
    """

    default_comparison = {
        "available": False,
        "baseline_scan": "N/A",
        "comparison_scan": "N/A",
        "host_ip": "N/A",

        "baseline_findings": 0,
        "comparison_findings": 0,
        "baseline_unique_findings": 0,
        "comparison_unique_findings": 0,

        "common_findings": 0,
        "baseline_only_findings": 0,
        "comparison_only_findings": 0,
        "additional_visibility": 0,

        "baseline_assets": 0,
        "comparison_assets": 0,

        "baseline_severity": {
            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0,
            "Info": 0,
        },

        "comparison_severity": {
            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0,
            "Info": 0,
        },
    }

    if not comparison_result:
        return default_comparison

    prepared = default_comparison.copy()

    prepared.update(comparison_result)

    prepared["available"] = True

    prepared["baseline_severity"] = {
        **default_comparison["baseline_severity"],
        **comparison_result.get(
            "baseline_severity",
            {}
        ),
    }

    prepared["comparison_severity"] = {
        **default_comparison["comparison_severity"],
        **comparison_result.get(
            "comparison_severity",
            {}
        ),
    }

    return prepared


def generate_report(
    df,
    output_path,
    comparison_result=None,
):
    """
    Generate the VulnPulse HTML vulnerability management report.

    Parameters
    ----------
    df : pandas.DataFrame
        Prioritized vulnerability findings.

    output_path : str or pathlib.Path
        Destination path for the generated HTML report.

    comparison_result : dict, optional
        Optional scan comparison data produced by
        vulnpulse.comparison.compare_findings().

    Returns
    -------
    pathlib.Path
        Path to the generated report.
    """

    # ----------------------------------------------------------
    # Paths
    # ----------------------------------------------------------

    output_path = Path(output_path)

    template_dir = (
        Path(__file__).resolve().parents[2]
        / "docs"
    )

    # ----------------------------------------------------------
    # Prepare Jinja environment
    # ----------------------------------------------------------

    environment = Environment(
        loader=FileSystemLoader(template_dir)
    )

    template = environment.get_template(
        "report.html"
    )

    # ----------------------------------------------------------
    # Prepare report data
    # ----------------------------------------------------------

    report_data = _prepare_report_data(df)

    comparison = _prepare_comparison_data(
        comparison_result
    )

    # ----------------------------------------------------------
    # Severity summary
    # ----------------------------------------------------------

    severity_order = [
        "Critical",
        "High",
        "Medium",
        "Low",
        "Info",
    ]

    severity_counts = {
        severity: int(
            (
                report_data["Severity"]
                == severity
            ).sum()
        )
        for severity in severity_order
    }

    # ----------------------------------------------------------
    # Asset summary
    # ----------------------------------------------------------

    asset_summary_df = (
        report_data
        .groupby(
            [
                "Hostname",
                "IP Address",
                "Platform",
                "Asset Criticality",
            ],
            dropna=False,
        )
        .size()
        .reset_index(
            name="Findings"
        )
    )

    asset_summary = (
        asset_summary_df
        .fillna("N/A")
        .to_dict(
            orient="records"
        )
    )

    # ----------------------------------------------------------
    # Top priority findings
    #
    # The DataFrame is already prioritized by the
    # risk module, so the first 10 records are
    # the highest-priority findings.
    # ----------------------------------------------------------

    top_df = report_data.head(10)

    top_findings = (
        top_df
        .to_dict(
            orient="records"
        )
    )

    # ----------------------------------------------------------
    # Complete finding dataset
    #
    # Used by the interactive Finding Explorer.
    # ----------------------------------------------------------

    all_findings = (
        report_data
        .to_dict(
            orient="records"
        )
    )

    # ----------------------------------------------------------
    # Render HTML
    # ----------------------------------------------------------

    html = template.render(
        total_findings=len(
            report_data
        ),
        total_assets=len(
            asset_summary
        ),
        severity_counts=severity_counts,
        asset_summary=asset_summary,
        top_findings=top_findings,
        all_findings=all_findings,
        comparison=comparison,
    )

    # ----------------------------------------------------------
    # Ensure output directory exists
    # ----------------------------------------------------------

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    # ----------------------------------------------------------
    # Write report
    # ----------------------------------------------------------

    output_path.write_text(
        html,
        encoding="utf-8"
    )

    return output_path