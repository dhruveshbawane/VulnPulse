import pandas as pd


SEVERITY_MAPPING = {
    4: "Critical",
    3: "High",
    2: "Medium",
    1: "Low",
    0: "Info"
}


def get_target_host(scan_results):
    """Extract the target hostname/IP from scan results."""

    hosts = scan_results.get("hosts", [])

    if not hosts:
        return "Unknown"

    return hosts[0].get(
        "hostname",
        "Unknown"
    )


def parse_vulnerabilities(scan_results):
    """Normalize Nessus vulnerability records into a DataFrame."""

    hostname = get_target_host(scan_results)

    vulnerabilities = scan_results.get(
        "vulnerabilities",
        []
    )

    rows = []

    for vulnerability in vulnerabilities:

        severity_number = vulnerability.get(
            "severity"
        )

        severity_name = SEVERITY_MAPPING.get(
            severity_number,
            "Unknown"
        )

        fallback_score = vulnerability.get(
            "isFallBackScore",
            False
        )

        cvss_version = (
            "CVSS v2"
            if fallback_score
            else "CVSS"
        )

        rows.append({
            "Host": hostname,
            "Plugin ID": vulnerability.get("plugin_id"),
            "Vulnerability": vulnerability.get(
                "plugin_name"
            ),
            "Severity": severity_name,
            "Severity Score": severity_number,
            "CVSS": vulnerability.get("score"),
            "CVSS Version": cvss_version,
            "VPR": vulnerability.get("vpr_score"),
            "EPSS": vulnerability.get("epss_score"),
            "Plugin Family": vulnerability.get(
                "plugin_family"
            ),
            "Count": vulnerability.get("count")
        })

    df = pd.DataFrame(rows)

    if df.empty:
        raise RuntimeError(
            "No vulnerability records were returned."
        )

    for column in ["CVSS", "VPR", "EPSS"]:
        df[column] = pd.to_numeric(
            df[column],
            errors="coerce"
        )

    return df