import pandas as pd

from src.vulnpulse.comparison import (
    compare_findings,
)


def test_compare_findings():
    baseline_df = pd.DataFrame({
        "IP Address": [
            "192.168.84.129",
            "192.168.84.129",
            "192.168.84.128",
        ],
        "Plugin ID": [
            1001,
            1002,
            2001,
        ],
        "Severity": [
            "Info",
            "Info",
            "Critical",
        ],
    })

    credentialed_df = pd.DataFrame({
        "IP Address": [
            "192.168.84.129",
            "192.168.84.129",
            "192.168.84.129",
            "192.168.84.129",
        ],
        "Plugin ID": [
            1001,
            1002,
            1003,
            1004,
        ],
        "Severity": [
            "Info",
            "Info",
            "High",
            "Critical",
        ],
    })

    result = compare_findings(
        baseline_df,
        credentialed_df,
    )

    assert result["baseline_findings"] == 3
    assert result["comparison_findings"] == 4

    assert (
        result["baseline_unique_findings"]
        == 3
    )

    assert (
        result["comparison_unique_findings"]
        == 4
    )

    assert result["common_findings"] == 2

    assert (
        result["baseline_only_findings"]
        == 1
    )

    assert (
        result["comparison_only_findings"]
        == 2
    )

    assert (
        result["additional_visibility"]
        == 2
    )

    assert result["baseline_assets"] == 2
    assert result["comparison_assets"] == 1

    assert result["baseline_severity"] == {
        "Critical": 1,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Info": 2,
    }

    assert result["comparison_severity"] == {
        "Critical": 1,
        "High": 1,
        "Medium": 0,
        "Low": 0,
        "Info": 2,
    }


def test_compare_empty_datasets():
    baseline_df = pd.DataFrame(
        columns=[
            "IP Address",
            "Plugin ID",
            "Severity",
        ]
    )

    comparison_df = pd.DataFrame(
        columns=[
            "IP Address",
            "Plugin ID",
            "Severity",
        ]
    )

    result = compare_findings(
        baseline_df,
        comparison_df,
    )

    assert result["baseline_findings"] == 0
    assert result["comparison_findings"] == 0
    assert result["common_findings"] == 0
    assert result["baseline_only_findings"] == 0
    assert result["comparison_only_findings"] == 0
    assert result["additional_visibility"] == 0