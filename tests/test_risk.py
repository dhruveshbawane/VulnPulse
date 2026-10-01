import pandas as pd

from src.vulnpulse.risk import prioritize_findings


def test_priority_score_is_calculated():
    df = pd.DataFrame([
        {
            "Vulnerability": "Critical vulnerability",
            "Severity Score": 4,
            "CVSS": 10.0,
            "VPR": 8.0,
            "EPSS": 0.9,
        }
    ])

    result = prioritize_findings(df, asset_criticality=3)

    assert result.iloc[0]["Asset Criticality"] == 3
    assert result.iloc[0]["Priority Score"] == 12


def test_custom_asset_criticality():
    df = pd.DataFrame([
        {
            "Vulnerability": "High vulnerability",
            "Severity Score": 3,
            "CVSS": 7.5,
            "VPR": 5.0,
            "EPSS": 0.5,
        }
    ])

    result = prioritize_findings(df, asset_criticality=5)

    assert result.iloc[0]["Asset Criticality"] == 5
    assert result.iloc[0]["Priority Score"] == 15


def test_findings_are_sorted_by_priority():
    df = pd.DataFrame([
        {
            "Vulnerability": "Low priority",
            "Severity Score": 1,
            "CVSS": 3.0,
            "VPR": 2.0,
            "EPSS": 0.1,
        },
        {
            "Vulnerability": "High priority",
            "Severity Score": 4,
            "CVSS": 10.0,
            "VPR": 8.0,
            "EPSS": 0.9,
        },
        {
            "Vulnerability": "Medium priority",
            "Severity Score": 2,
            "CVSS": 6.0,
            "VPR": 4.0,
            "EPSS": 0.4,
        },
    ])

    result = prioritize_findings(df, asset_criticality=3)

    assert list(result["Vulnerability"]) == [
        "High priority",
        "Medium priority",
        "Low priority",
    ]


def test_original_dataframe_is_not_modified():
    df = pd.DataFrame([
        {
            "Vulnerability": "Test vulnerability",
            "Severity Score": 4,
            "CVSS": 10.0,
            "VPR": 8.0,
            "EPSS": 0.9,
        }
    ])

    original_columns = list(df.columns)

    prioritize_findings(df)

    assert list(df.columns) == original_columns
    assert "Priority Score" not in df.columns
    assert "Asset Criticality" not in df.columns

def test_prioritize_findings_per_asset_criticality():
    import pandas as pd

    df = pd.DataFrame({
        "IP Address": [
            "192.168.84.128",
            "192.168.84.129",
            "192.168.84.130",
        ],
        "Severity Score": [
            4,
            4,
            4,
        ],
        "CVSS": [
            10.0,
            10.0,
            10.0,
        ],
        "VPR": [
            8.0,
            8.0,
            8.0,
        ],
        "EPSS": [
            0.9,
            0.9,
            0.9,
        ],
    })

    asset_criticality = {
        "192.168.84.128": 3,
        "192.168.84.129": 2,
        "192.168.84.130": 1,
    }

    result = prioritize_findings(
        df,
        asset_criticality=asset_criticality
    )

    assert list(result["Asset Criticality"]) == [
        3,
        2,
        1,
    ]

    assert list(result["Priority Score"]) == [
        12,
        8,
        4,
    ]