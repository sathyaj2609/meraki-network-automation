# Meraki Network Automation Suite

A Python automation suite for auditing and reporting on Cisco Meraki
organizations, networks, devices, and wireless SSIDs via the Meraki
Dashboard API (cloud-managed REST API -- no SSH/CLI access required).

## Features

- List all Meraki organizations accessible to your API key
- List all networks within an organization
- List all devices within each network
- List enabled wireless SSIDs (with auth mode) within each network
- CLI flags to run the full audit or target specific sections
- Structured logging to console and file (`logs/meraki_client.log`)
- Graceful handling of empty results (e.g. networks with no devices)
  and API errors (invalid key, unreachable API)

## Folder structure

src/
meraki_client.py      # Core client: API session, org/network/device/SSID listing, CLI
logs/
meraki_client.log     # Structured runtime logs
reports/                  # (reserved for future CSV/JSON export output)
tests/                    # Unit tests
.env.example               # Template for MERAKI_API_KEY
requirements.txt

## Project Status

- **Day 1** — Complete. Project structure, `.env` config, initial README.
- **Day 2** — Complete. `src/meraki_client.py` built with `list_organizations`, `list_networks`, `list_devices`, `list_ssids`; argparse CLI (`--list-orgs`, `--list-networks`, `--list-devices`, `--list-ssids`); structured logging; graceful error/empty-state handling. Live-tested end-to-end against a personal Meraki organization and two test networks.

## Usage

python src/meraki_client.py --list-orgs
python src/meraki_client.py --list-networks
python src/meraki_client.py --list-devices
python src/meraki_client.py --list-ssids
python src/meraki_client.py --export json
python src/meraki_client.py --export csv

Running with no flags performs the full audit (orgs, networks, devices, SSIDs) and prints results as console tables. Add `--export json` or `--export csv` to also write results to the `reports/` folder — JSON as a single nested file, CSV as one flat file per category (organizations, networks, devices, SSIDs), skipping any category with no data.

Requires a `MERAKI_API_KEY` set in a `.env` file (see `.env.example`).


