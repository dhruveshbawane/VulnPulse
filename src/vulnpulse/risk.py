def prioritize_findings(df, asset_criticality=3):
    """
    Calculate the baseline VulnPulse priority score.

    Priority Score =
        Severity Score × Asset Criticality
    """

    df = df.copy()

    df["Asset Criticality"] = asset_criticality

    df["Priority Score"] = (
        df["Severity Score"]
        * df["Asset Criticality"]
    )

    df = df.sort_values(
        by=[
            "Priority Score",
            "CVSS",
            "VPR",
            "EPSS"
        ],
        ascending=[
            False,
            False,
            False,
            False
        ],
        na_position="last"
    )

    return df