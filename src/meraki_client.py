"""
meraki_client.py

Core Meraki Dashboard API connection logic.

Responsibilities:
    - Load MERAKI_API_KEY from the environment (.env) and build a
      DashboardAPI session.
    - List the organizations the key has access to, and the networks
      within a given organization.
    - Fail loudly (with a single, catchable exception) when the key is
      missing/invalid or the API can't be reached, so callers (e.g. a
      future audit/report script that walks org -> network -> device)
      can decide whether to retry, skip, or abort.

Unlike SSH-based device automation, there's no per-device connection
here. DashboardAPI() opens one authenticated HTTPS session that every
call reuses -- listing organizations, networks, and (later) devices are
all just different endpoints on that same session. Building the client
is therefore split out (get_dashboard) from using it (list_organizations,
list_networks), so the session is created once and passed around instead
of being rebuilt per call.
"""

import argparse
import logging
import os
import sys
from pathlib import Path

import meraki
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table

# Load variables from .env into the process environment as soon as this
# module is imported. python-dotenv silently no-ops if .env doesn't
# exist, which keeps this safe to import in contexts (like tests) where
# credentials aren't needed.
load_dotenv()

# Module-level logger, named after this file. We intentionally do NOT
# call logging.basicConfig() here -- configuring handlers/formatters is
# the application's job, not a library module's. Handler setup lives in
# the __main__ block below instead.
logger = logging.getLogger(__name__)


class MerakiClientError(Exception):
    """Raised when we fail to authenticate or reach the Meraki API.

    Wraps meraki.APIError/meraki-key errors so callers can catch one
    thing (this) instead of needing to know the SDK's exception
    hierarchy, while the original error is still available via
    `__cause__` for debugging/logging.
    """


def get_dashboard() -> meraki.DashboardAPI:
    """Build an authenticated Meraki DashboardAPI session.

    Reads MERAKI_API_KEY from the environment (populated by load_dotenv()
    above) rather than letting the SDK read its own default env var
    (MERAKI_DASHBOARD_API_KEY), so this project's .env convention stays
    in our control.

    Raises:
        MerakiClientError: if MERAKI_API_KEY isn't set.
    """
    api_key = os.environ.get("MERAKI_API_KEY")
    if not api_key:
        raise MerakiClientError(
            "MERAKI_API_KEY is not set. Copy .env.example to .env and add your key."
        )

    logger.info("Initializing Meraki DashboardAPI session...")
    # suppress_logging=True: the SDK ships its own logger that (by
    # default) writes a timestamped log file to the working directory
    # and echoes every request/response to the console. We disable it
    # and rely on our own logger below for connection attempts/results,
    # matching how the rest of this project handles logging.
    dashboard = meraki.DashboardAPI(api_key=api_key, suppress_logging=True)
    logger.info("DashboardAPI session ready.")
    return dashboard


def list_organizations(dashboard: meraki.DashboardAPI) -> list:
    """Return every organization the API key has access to."""
    logger.info("Fetching organizations...")
    try:
        organizations = dashboard.organizations.getOrganizations(total_pages="all")
    except meraki.APIError as exc:
        raise MerakiClientError(_describe_api_error(exc)) from exc

    logger.info("Found %d organization(s).", len(organizations))
    return organizations


def list_networks(dashboard: meraki.DashboardAPI, organization_id: str) -> list:
    """Return every network within the given organization."""
    logger.info("Fetching networks for organization %s...", organization_id)
    try:
        networks = dashboard.organizations.getOrganizationNetworks(
            organization_id, total_pages="all"
        )
    except meraki.APIError as exc:
        raise MerakiClientError(_describe_api_error(exc)) from exc

    logger.info("Found %d network(s) in organization %s.", len(networks), organization_id)
    return networks
def list_devices(dashboard: meraki.DashboardAPI, network_id: str) -> list:
    """Return every device within the given network."""
    logger.info("Fetching devices for network %s...", network_id)
    try:
        devices = dashboard.networks.getNetworkDevices(network_id)
    except meraki.APIError as exc:
        raise MerakiClientError(_describe_api_error(exc)) from exc
    logger.info("Found %d device(s) in network %s.", len(devices), network_id)
    return devices

def list_ssids(dashboard: meraki.DashboardAPI, network_id: str) -> list:
    """Return every wireless SSID configured on the given network.
    Meraki networks always have a fixed set of SSID slots (commonly 15),
    most of which are disabled by default. We return all of them here;
    callers can filter by "enabled" if they only care about active SSIDs.
    """
    logger.info("Fetching SSIDs for network %s...", network_id)
    try:
        ssids = dashboard.wireless.getNetworkWirelessSsids(network_id)
    except meraki.APIError as exc:
        raise MerakiClientError(_describe_api_error(exc)) from exc
    enabled_count = sum(1 for ssid in ssids if ssid.get("enabled"))
    logger.info(
        "Found %d SSID slot(s) in network %s (%d enabled).",
        len(ssids), network_id, enabled_count,
    )
    return ssids


def _describe_api_error(exc: meraki.APIError) -> str:
    """Translate a meraki.APIError into a clear, situation-specific message.

    The SDK collapses HTTP errors *and* connection failures (DNS, timeout,
    no route) into the same APIError after exhausting its retries, so we
    branch on status to tell the two apart for the log/error message.
    """
    if exc.status == 401:
        return "Meraki API rejected the request: invalid or revoked API key."
    if exc.status is None:
        return f"Could not reach the Meraki API (connection issue): {exc.reason}"
    return f"Meraki API error {exc.status}: {exc.reason} - {exc.message}"

def parse_args() -> argparse.Namespace:
    """Define and parse command-line flags for this script.
    No flags -> run everything (orgs, networks, devices, SSIDs), which
    matches the "just show me what's out there" default a first-time
    user expects. Passing any specific --list-* flag narrows the run to
    only those sections, useful for quick checks or scripting.
    """
    parser = argparse.ArgumentParser(
        description="Cisco Meraki Dashboard API automation CLI."
    )
    parser.add_argument(
        "--list-orgs", action="store_true", help="List organizations only."
    )
    parser.add_argument(
        "--list-networks", action="store_true",
        help="List networks in the first organization.",
    )
    parser.add_argument(
        "--list-devices", action="store_true",
        help="List devices in each network.",
    )
    parser.add_argument(
        "--list-ssids", action="store_true",
        help="List enabled wireless SSIDs in each network.",
    )
    args = parser.parse_args()

    # If the user didn't pass any specific --list-* flag, run all of them.
    if not any([args.list_orgs, args.list_networks, args.list_devices, args.list_ssids]):
        args.list_orgs = args.list_networks = args.list_devices = args.list_ssids = True

    return args


if __name__ == "__main__":
    # Application-level logging setup: log to both the console and a
    # file under logs/, so a scheduled/unattended run still leaves a
    # record even if nobody watches the console.
    project_root = Path(__file__).resolve().parent.parent
    log_dir = project_root / "logs"
    log_dir.mkdir(exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler(log_dir / "meraki_client.log"),
        ],
    )
    console = Console()
    args = parse_args()

    try:
        dashboard = get_dashboard()
        organizations = list_organizations(dashboard)
    except MerakiClientError as exc:
        logger.error(str(exc))
        sys.exit(1)

    if not organizations:
        logger.warning("API key is valid, but has no organizations to show.")
        sys.exit(0)

    if args.list_orgs:
        org_table = Table(title="Meraki Organizations")
        org_table.add_column("Name", style="cyan")
        org_table.add_column("ID", style="magenta")
        for org in organizations:
            org_table.add_row(org.get("name", "-"), str(org.get("id", "-")))
        console.print(org_table)

    # Networks, devices, and SSIDs all need the first org's networks, so
    # fetch them whenever any of those three flags is set.
    if args.list_networks or args.list_devices or args.list_ssids:
        first_org = organizations[0]
        org_id = first_org.get("id")
        org_name = first_org.get("name", org_id)

        try:
            networks = list_networks(dashboard, org_id)
        except MerakiClientError as exc:
            logger.error(str(exc))
            sys.exit(1)

        if args.list_networks:
            net_table = Table(title=f"Networks in '{org_name}'")
            net_table.add_column("Name", style="cyan")
            net_table.add_column("ID", style="magenta")
            net_table.add_column("Product Types", style="green")
            net_table.add_column("Time Zone", style="yellow")
            for net in networks:
                net_table.add_row(
                    net.get("name", "-"),
                    str(net.get("id", "-")),
                    ", ".join(net.get("productTypes", [])) or "-",
                    net.get("timeZone", "-"),
                )
            console.print(net_table)

        for net in networks:
            net_id = net.get("id")
            net_name = net.get("name", net_id)

            if args.list_devices:
                try:
                    devices = list_devices(dashboard, net_id)
                except MerakiClientError as exc:
                    logger.error(str(exc))
                else:
                    if not devices:
                        console.print(f"[dim]No devices found in '{net_name}'.[/dim]")
                    else:
                        device_table = Table(title=f"Devices in '{net_name}'")
                        device_table.add_column("Name", style="cyan")
                        device_table.add_column("Model", style="magenta")
                        device_table.add_column("Serial", style="green")
                        device_table.add_column("Status", style="yellow")
                        for device in devices:
                            device_table.add_row(
                                device.get("name", "-"),
                                device.get("model", "-"),
                                device.get("serial", "-"),
                                device.get("status", "-"),
                            )
                        console.print(device_table)

            if args.list_ssids:
                try:
                    ssids = list_ssids(dashboard, net_id)
                except MerakiClientError as exc:
                    logger.error(str(exc))
                else:
                    enabled_ssids = [s for s in ssids if s.get("enabled")]
                    if not enabled_ssids:
                        console.print(f"[dim]No enabled SSIDs found in '{net_name}'.[/dim]")
                    else:
                        ssid_table = Table(title=f"Wireless SSIDs in '{net_name}'")
                        ssid_table.add_column("Number", style="cyan")
                        ssid_table.add_column("Name", style="magenta")
                        ssid_table.add_column("Enabled", style="green")
                        ssid_table.add_column("Auth Mode", style="yellow")
                        for ssid in enabled_ssids:
                            ssid_table.add_row(
                                str(ssid.get("number", "-")),
                                ssid.get("name", "-"),
                                str(ssid.get("enabled", "-")),
                                ssid.get("authMode", "-"),
                            )
                        console.print(ssid_table)
