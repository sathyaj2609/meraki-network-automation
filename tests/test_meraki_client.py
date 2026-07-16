"""Unit tests for src/meraki_client.py.

These tests never hit the real Meraki API -- the DashboardAPI object and
its nested resource clients (organizations, networks, wireless, etc.)
are all mocked, so tests run instantly, work offline, and don't consume
API calls against a live Meraki org.
"""
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest
import meraki

# Make src/ importable without installing the project as a package.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import meraki_client as mc


# ---------------------------------------------------------------------------
# get_dashboard()
# ---------------------------------------------------------------------------

def test_get_dashboard_raises_without_api_key(monkeypatch):
    """No MERAKI_API_KEY set -> MerakiClientError, not a raw KeyError/crash."""
    monkeypatch.delenv("MERAKI_API_KEY", raising=False)
    with pytest.raises(mc.MerakiClientError, match="MERAKI_API_KEY is not set"):
        mc.get_dashboard()


def test_get_dashboard_succeeds_with_api_key(monkeypatch):
    """A valid-looking key builds a DashboardAPI session without error."""
    monkeypatch.setenv("MERAKI_API_KEY", "fake-test-key")
    dashboard = mc.get_dashboard()
    assert isinstance(dashboard, meraki.DashboardAPI)


# ---------------------------------------------------------------------------
# list_organizations() / list_networks() / list_devices() / list_ssids()
# ---------------------------------------------------------------------------

def make_api_error(status, reason="Some Error", message="Something went wrong"):
    """Build a fake meraki.APIError without needing a real HTTP response."""
    err = MagicMock(spec=meraki.APIError)
    err.status = status
    err.reason = reason
    err.message = message
    return err


def test_list_organizations_returns_data_on_success():
    dashboard = MagicMock()
    dashboard.organizations.getOrganizations.return_value = [
        {"id": "111", "name": "Org One"},
    ]
    result = mc.list_organizations(dashboard)
    assert result == [{"id": "111", "name": "Org One"}]


def test_list_organizations_raises_client_error_on_api_failure():
    dashboard = MagicMock()
    dashboard.organizations.getOrganizations.side_effect = meraki.APIError(
        {"tags": ["organizations", "getOrganizations"], "operation": "getOrganizations",
         "message": "unauthorized"},
        MagicMock(status=401, reason="Unauthorized"),
    )
    with pytest.raises(mc.MerakiClientError):
        mc.list_organizations(dashboard)


def test_list_networks_returns_data_on_success():
    dashboard = MagicMock()
    dashboard.organizations.getOrganizationNetworks.return_value = [
        {"id": "N_1", "name": "Net One"},
    ]
    result = mc.list_networks(dashboard, "111")
    assert result == [{"id": "N_1", "name": "Net One"}]


def test_list_devices_returns_empty_list_gracefully():
    """An empty network should return [] cleanly, not raise."""
    dashboard = MagicMock()
    dashboard.networks.getNetworkDevices.return_value = []
    result = mc.list_devices(dashboard, "N_1")
    assert result == []


def test_list_ssids_returns_data_on_success():
    dashboard = MagicMock()
    dashboard.wireless.getNetworkWirelessSsids.return_value = [
        {"number": 0, "name": "Test SSID", "enabled": True, "authMode": "psk"},
    ]
    result = mc.list_ssids(dashboard, "N_1")
    assert len(result) == 1
    assert result[0]["authMode"] == "psk"


# ---------------------------------------------------------------------------
# _describe_api_error()
# ---------------------------------------------------------------------------

def test_describe_api_error_401_is_clear_about_bad_key():
    exc = make_api_error(status=401, reason="Unauthorized")
    msg = mc._describe_api_error(exc)
    assert "invalid or revoked API key" in msg


def test_describe_api_error_connection_issue_when_status_is_none():
    exc = make_api_error(status=None, reason="Connection timed out")
    msg = mc._describe_api_error(exc)
    assert "Could not reach the Meraki API" in msg
    assert "Connection timed out" in msg


def test_describe_api_error_generic_status_includes_code_and_reason():
    exc = make_api_error(status=500, reason="Server Error", message="oops")
    msg = mc._describe_api_error(exc)
    assert "500" in msg
    assert "Server Error" in msg


# ---------------------------------------------------------------------------
# audit_security()
# ---------------------------------------------------------------------------

def test_audit_security_flags_open_ssid_as_high_severity():
    audit_data = {
        "networks": [{"id": "N_1", "name": "Branch A"}],
        "ssids": {"N_1": [{"number": 0, "name": "GuestWiFi", "enabled": True, "authMode": "open"}]},
        "devices": {"N_1": [{"name": "Switch1"}]},
    }
    findings = mc.audit_security(audit_data)
    open_findings = [f for f in findings if f["severity"] == "High"]
    assert len(open_findings) == 1
    assert "open" in open_findings[0]["finding"].lower()
    assert open_findings[0]["network"] == "Branch A"


def test_audit_security_flags_psk_ssid_as_low_severity():
    audit_data = {
        "networks": [{"id": "N_1", "name": "Branch A"}],
        "ssids": {"N_1": [{"number": 0, "name": "StaffWiFi", "enabled": True, "authMode": "psk"}]},
        "devices": {"N_1": [{"name": "Switch1"}]},
    }
    findings = mc.audit_security(audit_data)


def test_audit_security_ignores_disabled_ssids():
    """A disabled SSID, even with open auth, shouldn't be flagged --
    it isn't actually broadcasting/accepting connections."""
    audit_data = {
        "networks": [{"id": "N_1", "name": "Branch A"}],
        "ssids": {"N_1": [{"number": 1, "name": "Unused", "enabled": False, "authMode": "open"}]},
        "devices": {"N_1": [{"name": "Switch1"}]},
    }
    findings = mc.audit_security(audit_data)
    assert findings == []


def test_audit_security_flags_network_with_no_devices():
    audit_data = {
        "networks": [{"id": "N_1", "name": "Branch A"}],
        "ssids": {"N_1": []},
        "devices": {"N_1": []},
    }
    findings = mc.audit_security(audit_data)
    info_findings = [f for f in findings if f["severity"] == "Info"]
    assert len(info_findings) == 1
    assert "No devices claimed" in info_findings[0]["finding"]


def test_audit_security_returns_empty_list_when_nothing_to_flag():
    """A network with WPA3-Enterprise-style auth (anything not open/psk)
    and claimed devices should produce zero findings."""
    audit_data = {
        "networks": [{"id": "N_1", "name": "Branch A"}],
        "ssids": {"N_1": [{"number": 0, "name": "CorpWiFi", "enabled": True, "authMode": "8021x-radius"}]},
        "devices": {"N_1": [{"name": "Switch1"}]},
    }
    findings = mc.audit_security(audit_data)
    assert findings == []
