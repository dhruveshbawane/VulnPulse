from pathlib import Path

from jinja2 import Environment, FileSystemLoader


def generate_report(df, output_path):
    """Generate an HTML vulnerability management report."""

    output_path = Path(output_path)

    template_dir = (
        Path(__file__).resolve().parents[2]
        / "docs"
    )

    environment = Environment(
        loader=FileSystemLoader(template_dir)
    )

    template = environment.get_template(
        "report.html"
    )

    severity_order = [
        "Critical",
        "High",
        "Medium",
        "Low",
        "Info"
    ]

    severity_counts = {
        severity: int(
            (df["Severity"] == severity).sum()
        )
        for severity in severity_order
    }

    # Prepare the top findings for the HTML report.
    report_df = df.head(10).copy()

    # Replace actual missing values.
    report_df = report_df.fillna("N/A")

    # Nessus/pandas data can sometimes contain the literal
    # string "nan". Convert those values to a readable N/A.
    report_df = report_df.replace(
        {
            "nan": "N/A",
            "NaN": "N/A",
            "None": "N/A",
            "null": "N/A",
        }
    )

    top_findings = report_df.to_dict(
        orient="records"
    )

    html = template.render(
        total_findings=len(df),
        severity_counts=severity_counts,
        top_findings=top_findings
    )

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    output_path.write_text(
        html,
        encoding="utf-8"
    )

    return output_path