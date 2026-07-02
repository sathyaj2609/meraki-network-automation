# Meraki Network Automation Suite

A Python automation suite for auditing and reporting on Cisco Meraki
organizations, networks, and devices via the Meraki Dashboard API
(cloud-managed REST API — no SSH/CLI access required).

## Folder structure

```
.
├── src/        # Python source code
├── reports/    # Generated reports/output (gitignored)
├── logs/       # Log output (gitignored)
├── tests/      # Unit tests
├── requirements.txt
├── .env.example
└── README.md
```

## Setup

1. Create and activate a virtual environment:
   ```
   python -m venv venv
   venv\Scripts\activate      # Windows
   source venv/bin/activate   # macOS/Linux
   ```

2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Copy `.env.example` to `.env` and set your Meraki API key:
   ```
   cp .env.example .env
   ```

## API key note

For testing and development, this project can use Cisco's official
public read-only demo API key, which provides access to a sample
Meraki organization without requiring a real Meraki account. See the
[Meraki API docs](https://developer.cisco.com/meraki/api-v1/) for
details. Swap in your own key in `.env` to run against a real
organization.
