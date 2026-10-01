import json
import os
from pathlib import Path

import requests
import urllib3
from dotenv import load_dotenv


class NessusClient:
    """Client for interacting with the local Nessus REST API."""

    def __init__(self):
        load_dotenv()

        self.base_url = os.getenv(
            "NESSUS_URL",
            "https://localhost:8834"
        ).rstrip("/")

        self.access_key = os.getenv("NESSUS_ACCESS_KEY")
        self.secret_key = os.getenv("NESSUS_SECRET_KEY")

        self.scan_name = os.getenv(
            "NESSUS_SCAN_NAME",
            "Metasploitable2 baseline"
        )

        self.verify_tls = (
            os.getenv("NESSUS_VERIFY_TLS", "false").lower()
            == "true"
        )

        if not self.access_key or not self.secret_key:
            raise RuntimeError(
                "Nessus API keys are missing. "
                "Check your .env file."
            )

        self.session = requests.Session()

        self.session.headers.update({
            "X-ApiKeys": (
                f"accessKey={self.access_key}; "
                f"secretKey={self.secret_key}"
            ),
            "Accept": "application/json"
        })

        self.session.verify = self.verify_tls

        if not self.verify_tls:
            urllib3.disable_warnings(
                urllib3.exceptions.InsecureRequestWarning
            )

    def get_scans(self):
        """Return the scans available to the API account."""

        response = self.session.get(
            f"{self.base_url}/scans",
            timeout=30
        )

        response.raise_for_status()

        return response.json().get("scans", [])

    def find_scan(self):
        """Find the configured Nessus scan."""

        scans = self.get_scans()

        matching_scans = [
            scan
            for scan in scans
            if scan.get("name") == self.scan_name
        ]

        if not matching_scans:
            raise RuntimeError(
                f'Could not find scan "{self.scan_name}"'
            )

        return matching_scans[-1]

    def download_scan(self, scan_id):
        """Download complete scan results."""

        response = self.session.get(
            f"{self.base_url}/scans/{scan_id}",
            timeout=120
        )

        response.raise_for_status()

        return response.json()

    def get_host_details(self, scan_id, host_id):
        """Download vulnerability results for one specific host."""

        response = self.session.get(
            f"{self.base_url}/scans/{scan_id}/hosts/{host_id}",
            timeout=60
        )

        response.raise_for_status()

        return response.json()

    @staticmethod
    def save_raw_scan(scan_results, output_path):
        """Save raw Nessus JSON to disk."""

        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        with path.open(
            "w",
            encoding="utf-8"
        ) as file:
            json.dump(
                scan_results,
                file,
                indent=2
            )