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