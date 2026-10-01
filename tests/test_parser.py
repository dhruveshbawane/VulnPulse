import pandas as pd
import pytest

from src.vulnpulse.parser import (
    get_target_host,
    parse_vulnerabilities,
)


def test_get_target_host():
    scan_results = {
        "hosts": [
            {
                "hostname": "192.168.84.128"
            }
        ]
    }

    assert get_target_host(
        scan_results
    ) == "192.168.84.128"


def test_get_target_host_when_no_hosts():
    scan_results = {
        "hosts": []
    }

    assert get_target_host(
        scan_results
    ) == "Unknown"


def test_parse_vulnerabilities():
    scan_results = {
        "hosts": [
            {
                "hostname": "192.168.84.128"
            }
        ],
        "vulnerabilities": [
            {
                "plugin_id": 12345,
                "plugin_name": "Test Vulnerability",
                "severity": 4,
                "score": 10.0,
                "vpr_score": 8.5,
                "epss_score": 0.95,
                "plugin_family": "Test",
                "count": 1,
                "isFallBackScore": False,
            }
        ],
    }

    df = parse_vulnerabilities(
        scan_results
    )

    assert isinstance(
        df,
        pd.DataFrame
    )

    assert len(df) == 1

    assert df.iloc[0]["Hostname"] == (
        "192.168.84.128"
    )

    assert df.iloc[0]["Plugin ID"] == 12345

    assert df.iloc[0]["Vulnerability"] == (
        "Test Vulnerability"
    )

    assert df.iloc[0]["Severity"] == (
        "Critical"
    )

    assert df.iloc[0]["Severity Score"] == 4

    assert df.iloc[0]["CVSS"] == 10.0

    assert df.iloc[0]["VPR"] == 8.5

    assert df.iloc[0]["EPSS"] == 0.95


def test_parse_vulnerabilities_with_details():
    scan_results = {
        "hosts": [
            {
                "hostname": "192.168.84.128"
            }
        ],
        "vulnerabilities": [
            {
                "plugin_id": 134862,
                "plugin_name": (
                    "Apache Tomcat AJP Connector "
                    "Request Injection (Ghostcat)"
                ),
                "severity": 3,
                "score": 9.8,
                "vpr_score": 7.9,
                "epss_score": 0.99,
                "plugin_family": "Web Servers",
                "count": 1,
                "isFallBackScore": False,
            }
        ],
        "prioritization": {
            "plugins": [
                {
                    "pluginid": "134862",
                    "pluginname": (
                        "Apache Tomcat AJP Connector "
                        "Request Injection (Ghostcat)"
                    ),
                    "hosts": [
                        {
                            "host_ip": "192.168.84.128",
                            "hostname": "192.168.84.128",
                            "id": 2,
                        }
                    ],
                    "pluginattributes": {
                        "description": (
                            "A vulnerable AJP connector "
                            "was detected."
                        ),
                        "solution": (
                            "Upgrade Tomcat to a "
                            "patched version."
                        ),
                        "required_port": "8009",
                        "exploit_code_maturity": (
                            "High"
                        ),
                        "ref_information": {
                            "ref": [
                                {
                                    "name": "cve",
                                    "values": {
                                        "value": [
                                            "CVE-2020-1938"
                                        ]
                                    },
                                }
                            ]
                        },
                        "vuln_information": {
                            "exploit_available": (
                                "true"
                            )
                        },
                    },
                }
            ]
        },
    }

    df = parse_vulnerabilities(
        scan_results
    )

    assert len(df) == 1

    assert df.iloc[0]["Hostname"] == (
        "192.168.84.128"
    )

    assert df.iloc[0]["IP Address"] == (
        "192.168.84.128"
    )

    assert df.iloc[0]["Description"] == (
        "A vulnerable AJP connector was detected."
    )

    assert df.iloc[0]["Solution"] == (
        "Upgrade Tomcat to a patched version."
    )

    assert df.iloc[0]["CVEs"] == (
        "CVE-2020-1938"
    )

    assert df.iloc[0]["Port"] == "8009"

    assert df.iloc[0]["Exploit Available"] == (
        "true"
    )

    assert df.iloc[0]["Exploit Maturity"] == (
        "High"
    )


def test_parse_vulnerabilities_multiple_hosts():
    scan_results = {
        "hosts": [
            {
                "hostname": "192.168.84.128"
            },
            {
                "hostname": "192.168.84.129"
            },
        ],
        "vulnerabilities": [
            {
                "plugin_id": 12345,
                "plugin_name": "Shared Vulnerability",
                "severity": 4,
                "score": 10.0,
                "vpr_score": 8.5,
                "epss_score": 0.95,
                "plugin_family": "Test",
                "count": 1,
                "isFallBackScore": False,
            }
        ],
        "prioritization": {
            "plugins": [
                {
                    "pluginid": "12345",
                    "hosts": [
                        {
                            "host_ip": "192.168.84.128",
                            "hostname": "192.168.84.128",
                            "id": 2,
                        },
                        {
                            "host_ip": "192.168.84.129",
                            "hostname": "192.168.84.129",
                            "id": 3,
                        },
                    ],
                    "pluginattributes": {},
                }
            ]
        },
    }

    df = parse_vulnerabilities(
        scan_results
    )

    assert len(df) == 2

    assert set(df["IP Address"]) == {
        "192.168.84.128",
        "192.168.84.129",
    }


def test_asset_inventory_overrides_nessus_hostname():
    scan_results = {
        "hosts": [
            {
                "hostname": "192.168.84.128"
            }
        ],
        "vulnerabilities": [
            {
                "plugin_id": 123,
                "plugin_name": "Test Vulnerability",
                "severity": 3,
                "score": 7.5,
                "vpr_score": 5.0,
                "epss_score": 0.5,
                "plugin_family": "Test",
                "count": 1,
            }
        ],
    }

    df = parse_vulnerabilities(
        scan_results,
        asset_inventory={
            "192.168.84.128": "MSF-LAB-01"
        }
    )

    assert df.iloc[0]["Hostname"] == (
        "MSF-LAB-01"
    )

    assert df.iloc[0]["IP Address"] == (
        "192.168.84.128"
    )


def test_parse_vulnerabilities_cvss_v2_fallback():
    scan_results = {
        "hosts": [
            {
                "hostname": "192.168.84.128"
            }
        ],
        "vulnerabilities": [
            {
                "plugin_id": 123,
                "plugin_name": "Old Vulnerability",
                "severity": 3,
                "score": 7.5,
                "isFallBackScore": True,
            }
        ],
    }

    df = parse_vulnerabilities(
        scan_results
    )

    assert df.iloc[0]["Severity"] == (
        "High"
    )

    assert df.iloc[0]["CVSS Version"] == (
        "CVSS v2"
    )


def test_parse_vulnerabilities_empty_results():
    scan_results = {
        "hosts": [],
        "vulnerabilities": [],
    }

    with pytest.raises(
        RuntimeError,
        match="No vulnerability records were returned.",
    ):
        parse_vulnerabilities(
            scan_results
        )

def test_parse_vulnerabilities_uses_host_id_for_host_attribution():
    scan_results = {
        "hosts": [
            {
                "host_id": 2,
                "hostname": "192.168.84.128",
            },
            {
                "host_id": 3,
                "hostname": "192.168.84.129",
            },
            {
                "host_id": 4,
                "hostname": "192.168.84.130",
            },
        ],
        "vulnerabilities": [
            {
                "host_id": 2,
                "plugin_id": 99999,
                "plugin_name": "Linux Test Vulnerability",
                "severity": 4,
                "score": 10.0,
                "vpr_score": None,
                "epss_score": None,
                "plugin_family": "Test",
                "count": 1,
                "isFallBackScore": False,
            },
        ],
    }

    df = parse_vulnerabilities(scan_results)

    assert len(df) == 1

    assert df.iloc[0]["IP Address"] == (
        "192.168.84.128"
    )

    assert df.iloc[0]["Hostname"] == (
        "192.168.84.128"
    )

    assert df.iloc[0]["Vulnerability"] == (
        "Linux Test Vulnerability"
    )