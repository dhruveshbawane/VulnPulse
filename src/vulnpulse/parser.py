import ipaddress

import pandas as pd


SEVERITY_MAPPING = {
    4: "Critical",
    3: "High",
    2: "Medium",
    1: "Low",
    0: "Info",
}


def _to_number(value):
    """Convert a value to float when possible."""

    if value is None:
        return None

    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _get_cvss_version(vulnerability):
    """Determine the CVSS version used by Nessus."""

    if vulnerability.get("isFallBackScore", False):
        return "CVSS v2"

    return "CVSS v3"


def _extract_references(plugin_attributes):
    """Extract CVE and CWE references from plugin attributes."""

    references = (
        plugin_attributes
        .get("ref_information", {})
        .get("ref", [])
    )

    cves = []
    cwes = []

    for reference in references:
        name = reference.get("name")

        values = (
            reference
            .get("values", {})
            .get("value", [])
        )

        if isinstance(values, str):
            values = [values]

        if name == "cve":
            cves.extend(values)

        elif name == "cwe":
            cwes.extend(values)

    return (
        ", ".join(dict.fromkeys(cves)),
        ", ".join(dict.fromkeys(cwes)),
    )


def _get_exploit_information(plugin_attributes):
    """Extract exploit-related information."""

    vuln_information = plugin_attributes.get(
        "vuln_information",
        {}
    )

    exploit_available = vuln_information.get(
        "exploit_available"
    )

    exploited_by_malware = plugin_attributes.get(
        "exploited_by_malware"
    )

    cisa_known_exploited = None

    references = (
        plugin_attributes
        .get("ref_information", {})
        .get("ref", [])
    )

    for reference in references:
        if reference.get("name") != "cisa-known-exploited":
            continue

        values = (
            reference
            .get("values", {})
            .get("value", [])
        )

        if isinstance(values, list) and values:
            cisa_known_exploited = values[0]

    return (
        exploit_available,
        exploited_by_malware,
        cisa_known_exploited,
    )


def _build_plugin_lookup(scan_results):
    """Build a lookup table for detailed Nessus plugin records."""

    lookup = {}

    prioritization = scan_results.get(
        "prioritization",
        {}
    )

    plugins = prioritization.get(
        "plugins",
        []
    )

    for plugin in plugins:
        plugin_id = plugin.get("pluginid")

        if plugin_id is None:
            plugin_attributes = plugin.get(
                "pluginattributes",
                {}
            )

            plugin_information = plugin_attributes.get(
                "plugin_information",
                {}
            )

            plugin_id = plugin_information.get(
                "plugin_id"
            )

        if plugin_id is not None:
            lookup[str(plugin_id)] = plugin

    return lookup


def _get_host_records(plugin, fallback_hosts):
    """Return hosts affected by a detailed plugin record."""

    if not plugin:
        return fallback_hosts

    hosts = plugin.get(
        "hosts",
        []
    )

    if hosts:
        return hosts

    return fallback_hosts


def _resolve_hostname(
    ip_address,
    nessus_hostname,
    asset_inventory=None
):
    """
    Resolve a display hostname.

    Asset inventory has priority. Nessus hostname is used next.
    IP address is the final fallback.
    """

    asset_inventory = asset_inventory or {}

    resolved_ip = ip_address

    if not resolved_ip and nessus_hostname:
        try:
            ipaddress.ip_address(
                nessus_hostname
            )
            resolved_ip = nessus_hostname

        except ValueError:
            pass

    if resolved_ip in asset_inventory:
        return asset_inventory[resolved_ip]

    if (
        nessus_hostname
        and nessus_hostname != resolved_ip
    ):
        return nessus_hostname

    return resolved_ip or "Unknown"


def get_target_host(scan_results):
    """Return the first target hostname from the scan."""

    hosts = scan_results.get(
        "hosts",
        []
    )

    if not hosts:
        return "Unknown"

    return hosts[0].get(
        "hostname",
        "Unknown"
    )


def parse_vulnerabilities(
    scan_results,
    asset_inventory=None
):
    """
    Parse Nessus vulnerability data into a pandas DataFrame.

    The parser combines Nessus vulnerability summary records
    with detailed plugin information when available.
    """

    vulnerabilities = scan_results.get(
        "vulnerabilities",
        []
    )

    if not vulnerabilities:
        raise RuntimeError(
            "No vulnerability records were returned."
        )

    fallback_hosts = scan_results.get(
        "hosts",
        []
    )

    plugin_lookup = _build_plugin_lookup(
        scan_results
    )

    rows = []

    for vulnerability in vulnerabilities:
        plugin_id = vulnerability.get(
            "plugin_id"
        )

        plugin = plugin_lookup.get(
            str(plugin_id)
        )

        plugin_attributes = {}

        if plugin:
            plugin_attributes = plugin.get(
                "pluginattributes",
                {}
            )

        cves, cwes = _extract_references(
            plugin_attributes
        )

        (
            exploit_available,
            exploited_by_malware,
            cisa_known_exploited,
        ) = _get_exploit_information(
            plugin_attributes
        )

        severity_number = vulnerability.get(
            "severity"
        )

        severity_name = SEVERITY_MAPPING.get(
            severity_number,
            "Unknown"
        )

        cvss_version = _get_cvss_version(
            vulnerability
        )

        hosts = _get_host_records(
            plugin,
            fallback_hosts
        )

        if not hosts:
            hosts = [
                {
                    "host_ip": None,
                    "hostname": None,
                }
            ]

        for host in hosts:
            ip_address = host.get(
                "host_ip"
            )

            nessus_hostname = host.get(
                "hostname"
            )

            # Some Nessus fallback host records do not
            # provide host_ip. If hostname contains an IP,
            # use it as the IP address.
            if not ip_address and nessus_hostname:
                try:
                    ipaddress.ip_address(
                        nessus_hostname
                    )

                    ip_address = nessus_hostname

                except ValueError:
                    pass

            hostname = _resolve_hostname(
                ip_address,
                nessus_hostname,
                asset_inventory
            )

            rows.append({
                "Hostname": hostname,
                "IP Address": ip_address,
                "Plugin ID": plugin_id,
                "Vulnerability": vulnerability.get(
                    "plugin_name"
                ),
                "Severity": severity_name,
                "Severity Score": severity_number,
                "CVSS": vulnerability.get(
                    "score"
                ),
                "CVSS Version": cvss_version,
                "VPR": vulnerability.get(
                    "vpr_score"
                ),
                "EPSS": vulnerability.get(
                    "epss_score"
                ),
                "Plugin Family": vulnerability.get(
                    "plugin_family"
                ),
                "Description": plugin_attributes.get(
                    "description"
                ),
                "Solution": plugin_attributes.get(
                    "solution"
                ),
                "CVEs": cves,
                "CWE": cwes,
                "Port": plugin_attributes.get(
                    "required_port"
                ),
                "Protocol": plugin_attributes.get(
                    "protocol"
                ),
                "Exploit Available": exploit_available,
                "Exploited By Malware": exploited_by_malware,
                "CISA Known Exploited": cisa_known_exploited,
                "Exploit Maturity": plugin_attributes.get(
                    "exploit_code_maturity"
                ),
                "Count": vulnerability.get(
                    "count"
                ),
            })

    df = pd.DataFrame(rows)

    if df.empty:
        raise RuntimeError(
            "No vulnerability records were returned."
        )

    for column in [
        "CVSS",
        "VPR",
        "EPSS",
    ]:
        df[column] = pd.to_numeric(
            df[column],
            errors="coerce"
        )

    return df