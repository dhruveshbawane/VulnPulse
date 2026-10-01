def prioritize_findings(
    df,
    asset_criticality=3
):
    """
    Calculate the VulnPulse priority score.

    Priority Score =
        Severity Score × Asset Criticality

    Asset criticality can be provided as:
    - a single number for all assets
    - a dictionary mapping IP addresses to criticality
    """

    df = df.copy()

    if isinstance(asset_criticality, dict):
        df["Asset Criticality"] = (
            df["IP Address"]
            .map(asset_criticality)
            .fillna(1)
        )
    else:
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