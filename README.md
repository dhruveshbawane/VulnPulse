# VulnPulse

VulnPulse is a Python-based vulnerability management pipeline that collects vulnerability data from Nessus, normalizes the results, prioritizes findings using vulnerability severity and asset criticality, and generates a readable HTML report.

The project was built as a hands-on security lab to understand the vulnerability management process from scanning to prioritization and reporting.

---

## What VulnPulse Does

VulnPulse performs the following workflow:

```text
Nessus
   ↓
Nessus REST API
   ↓
Host-specific vulnerability collection
   ↓
Vulnerability parsing and normalization
   ↓
Asset criticality mapping
   ↓
Priority score calculation
   ↓
Prioritized CSV
   ↓
HTML vulnerability report