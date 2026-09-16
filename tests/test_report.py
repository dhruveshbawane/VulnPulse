import pandas as pd

from src.vulnpulse.report import generate_report


def test_generate_report(tmp_path):
    df = pd.DataFrame([
        {
            "Host": "192.168.84.128",
            "Plugin ID": 123,
            "Vulnerability": "Test Critical Vulnerability",
            "Severity": "Critical",
            "Severity Score": 4,
            "CVSS": 10.0,
            "CVSS Version": "CVSS",
            "VPR": 8.0,
            "EPSS": 0.9,
            "Plugin Family": "Test",
            "Count": 1,
            "Asset Criticality": 3,
            "Priority Score": 12,
        },
        {
            "Host": "192.168.84.128",
            "Plugin ID": 456,
            "Vulnerability": "Test High Vulnerability",
            "Severity": "High",
            "Severity Score": 3,
            "CVSS": 7.5,
            "CVSS Version": "CVSS",
            "VPR": 5.0,
            "EPSS": 0.5,
            "Plugin Family": "Test",
            "Count": 1,
            "Asset Criticality": 3,
            "Priority Score": 9,
        },
    ])

    output_file = tmp_path / "report.html"

    result = generate_report(
        df,
        output_file
    )

    assert result == output_file
    assert output_file.exists()

    html = output_file.read_text(
        encoding="utf-8"
    )

    assert "VulnPulse" in html
    assert "Vulnerability Management Report" in html
    assert "Total Findings" in html
    assert "2" in html
    assert "Test Critical Vulnerability" in html
    assert "Test High Vulnerability" in html
    assert "10.0" in html
    assert "7.5" in html


def test_report_contains_severity_counts(tmp_path):
    df = pd.DataFrame([
        {
            "Severity": "Critical",
            "CVSS": 10.0,
            "VPR": 8.0,
            "EPSS": 0.9,
            "Vulnerability": "Critical Finding",
            "Priority Score": 12,
        },
        {
            "Severity": "Critical",
            "CVSS": 9.8,
            "VPR": 7.9,
            "EPSS": 0.8,
            "Vulnerability": "Another Critical Finding",
            "Priority Score": 12,
        },
        {
            "Severity": "High",
            "CVSS": 7.5,
            "VPR": 5.0,
            "EPSS": 0.5,
            "Vulnerability": "High Finding",
            "Priority Score": 9,
        },
    ])

    output_file = tmp_path / "report.html"

    generate_report(
        df,
        output_file
    )

    html = output_file.read_text(
        encoding="utf-8"
    )

    assert 'Critical' in html
    assert 'High' in html
    assert 'Medium' in html
    assert 'Low' in html
    assert 'Info' in html