import json

import pytest

from src.vulnpulse.nessus import NessusClient


def set_nessus_env(monkeypatch):
    monkeypatch.setenv(
        "NESSUS_ACCESS_KEY",
        "test_access_key"
    )
    monkeypatch.setenv(
        "NESSUS_SECRET_KEY",
        "test_secret_key"
    )
    monkeypatch.setenv(
        "NESSUS_URL",
        "https://localhost:8834"
    )
    monkeypatch.setenv(
        "NESSUS_SCAN_NAME",
        "Metasploitable2 baseline"
    )
    monkeypatch.setenv(
        "NESSUS_VERIFY_TLS",
        "false"
    )


class MockResponse:
    def __init__(self, data):
        self.data = data

    def raise_for_status(self):
        pass

    def json(self):
        return self.data


class MockSession:
    def __init__(self, response_data):
        self.response_data = response_data
        self.headers = {}
        self.verify = None
        self.requested_urls = []

    def get(self, url, timeout):
        self.requested_urls.append((url, timeout))
        return MockResponse(self.response_data)


def test_client_requires_api_keys(monkeypatch):
    # Use empty values so load_dotenv() does not replace them
    # with values from the real .env file.
    monkeypatch.setenv("NESSUS_ACCESS_KEY", "")
    monkeypatch.setenv("NESSUS_SECRET_KEY", "")

    with pytest.raises(
        RuntimeError,
        match="Nessus API keys are missing"
    ):
        NessusClient()


def test_get_scans(monkeypatch):
    set_nessus_env(monkeypatch)

    client = NessusClient()

    mock_session = MockSession({
        "scans": [
            {
                "id": 6,
                "name": "Metasploitable2 baseline"
            }
        ]
    })

    client.session = mock_session

    scans = client.get_scans()

    assert len(scans) == 1
    assert scans[0]["id"] == 6
    assert scans[0]["name"] == "Metasploitable2 baseline"

    assert mock_session.requested_urls[0][0] == (
        "https://localhost:8834/scans"
    )


def test_find_scan(monkeypatch):
    set_nessus_env(monkeypatch)

    client = NessusClient()

    mock_session = MockSession({
        "scans": [
            {
                "id": 1,
                "name": "Other Scan"
            },
            {
                "id": 6,
                "name": "Metasploitable2 baseline"
            }
        ]
    })

    client.session = mock_session

    scan = client.find_scan()

    assert scan["id"] == 6
    assert scan["name"] == "Metasploitable2 baseline"


def test_find_scan_when_scan_does_not_exist(monkeypatch):
    set_nessus_env(monkeypatch)

    client = NessusClient()

    client.session = MockSession({
        "scans": [
            {
                "id": 1,
                "name": "Different Scan"
            }
        ]
    })

    with pytest.raises(
        RuntimeError,
        match='Could not find scan "Metasploitable2 baseline"'
    ):
        client.find_scan()


def test_download_scan(monkeypatch):
    set_nessus_env(monkeypatch)

    client = NessusClient()

    scan_data = {
        "info": {
            "name": "Metasploitable2 baseline"
        },
        "hosts": [
            {
                "hostname": "192.168.84.128"
            }
        ],
        "vulnerabilities": []
    }

    mock_session = MockSession(scan_data)
    client.session = mock_session

    result = client.download_scan(6)

    assert result == scan_data

    assert mock_session.requested_urls[0][0] == (
        "https://localhost:8834/scans/6"
    )


def test_save_raw_scan(tmp_path):
    scan_data = {
        "info": {
            "name": "Test Scan"
        },
        "vulnerabilities": [
            {
                "plugin_id": 123,
                "plugin_name": "Test Vulnerability"
            }
        ]
    }

    output_file = tmp_path / "scan.json"

    NessusClient.save_raw_scan(
        scan_data,
        output_file
    )

    assert output_file.exists()

    with output_file.open(
        "r",
        encoding="utf-8"
    ) as file:
        saved_data = json.load(file)

    assert saved_data == scan_data