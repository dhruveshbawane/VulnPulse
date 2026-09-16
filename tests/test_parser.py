import pytest
import pandas as pd

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

    assert get_target_host(scan_results) == "192.168.84.128"


def test_get_target_host_when_no_hosts():
    scan_results = {
        "hosts": []
    }

    assert get_target_host(scan_results) == "Unknown"


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

    df = parse_vulnerabilities(scan_results)

    assert isinstance(df, pd.DataFrame)
    assert len(df) == 1

    assert df.iloc[0]["Host"] == "192.168.84.128"
    assert df.iloc[0]["Plugin ID"] == 12345
    assert df.iloc[0]["Vulnerability"] == "Test Vulnerability"
    assert df.iloc[0]["Severity"] == "Critical"
    assert df.iloc[0]["Severity Score"] == 4
    assert df.iloc[0]["CVSS"] == 10.0
    assert df.iloc[0]["VPR"] == 8.5
    assert df.iloc[0]["EPSS"] == 0.95


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

    df = parse_vulnerabilities(scan_results)

    assert df.iloc[0]["Severity"] == "High"
    assert df.iloc[0]["CVSS Version"] == "CVSS v2"


def test_parse_vulnerabilities_empty_results():
    scan_results = {
        "hosts": [],
        "vulnerabilities": [],
    }

    with pytest.raises(
        RuntimeError,
        match="No vulnerability records were returned."
    ):
        parse_vulnerabilities(scan_results)