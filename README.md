# VLAN Tunnel Automation Tool

This project is a CLI tool for tracing VLAN paths across mixed-vendor switches and applying VLAN/tagging changes hop-by-hop.

## What It Does

- Resolves switches by name/alias/IP (Zabbix lookup + inventory).
- Probes switch connectivity and captures full Telnet session logs.
- Looks up MAC addresses on supported vendors.
- Finds a free VLAN on L3 switches using vendor-specific rules.
- Builds a dry-run VLAN path plan (`plan`).
- Applies VLAN/tagging changes live (`deploy`).

Supported vendor drivers in current code:

- `cisco_ios`
- `snr`
- `eltex_mes`
- `arista`
- `generic_telnet` (fallback for basic session/probe use)

## Requirements

- Python 3.10+
- Network access to target switches over Telnet
- (Optional) Zabbix API access if Zabbix resolution is enabled

## Installation

```powershell
cd C:\path\to\vlan
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Configuration

Create your local config and environment files:

```powershell
Copy-Item config.example.yaml config.yaml
Copy-Item .env.example .env
```

### 1) `.env`

Set credentials and API settings in `.env`:

```dotenv
VLAN_TELNET_USERNAME=your_username
VLAN_TELNET_PASSWORD=your_password
VLAN_TELNET_SECRET=your_enable_secret

VLAN_ZABBIX_URL=https://zabbix.example.com/zabbix
VLAN_ZABBIX_API_TOKEN=your_api_token
# Optional fallback (if token is not used):
# VLAN_ZABBIX_USERNAME=api_user
# VLAN_ZABBIX_PASSWORD=api_password
```

### 2) `config.yaml`

```yaml
log_directory: logs

telnet:
  username_env: VLAN_TELNET_USERNAME
  password_env: VLAN_TELNET_PASSWORD
  secret_env: VLAN_TELNET_SECRET
  port: 23
  timeout_seconds: 20
  global_delay_factor: 1.5

zabbix:
  enabled: true
  url_env: VLAN_ZABBIX_URL
  api_token_env: VLAN_ZABBIX_API_TOKEN
  username_env: VLAN_ZABBIX_USERNAME
  password_env: VLAN_ZABBIX_PASSWORD
  search_field: host

vlan_ranges:
  - start: 116
    end: 299
  - start: 1025
    end: 1299

sites: []
inventory: []
vendors: {}
```

Notes:

- Secrets should stay in `.env`, not hardcoded in `config.yaml`.
- If `zabbix.enabled: true`, you must provide URL plus either API token or username/password.

## CLI Usage

Base help:

```powershell
python main.py --help
```

### Resolve a switch

```powershell
python main.py resolve SWITCH_NAME_OR_IP
```

### Probe a switch session

```powershell
python main.py probe SWITCH_NAME_OR_IP --debug
```

Optional manual L3 override during probe:

```powershell
python main.py probe SWITCH_NAME_OR_IP --l3 L3_SWITCH_NAME_OR_IP
```

### MAC lookup

```powershell
python main.py trace-mac SWITCH_NAME_OR_IP aa-bb-cc-dd-ee-ff
```

### Find free VLAN on an L3 switch

```powershell
python main.py find-vlan L3_SWITCH_NAME_OR_IP --debug
```

### Dry-run path planning

Auto-select VLAN:

```powershell
python main.py plan DEST_SWITCH DEST_PORT --debug
```

Fixed VLAN:

```powershell
python main.py plan DEST_SWITCH DEST_PORT --vlan 1200 --l3 L3_SWITCH
```

### Live deploy

```powershell
python main.py deploy DEST_SWITCH DEST_PORT --debug
```

Safe interactive mode (confirmation before connect/commands):

```powershell
python main.py deploy DEST_SWITCH DEST_PORT --confirm-steps
```

## Logs

- Session logs are written to `log_directory` (default: `logs/`).
- Filenames are generated as `<host>_YYYYMMDD_HHMMSS.log`.

## Optional Helper Script

The repository also contains `zabbix_name_ip_resolver.py` for direct Zabbix host/IP lookup.

Examples:

```powershell
python zabbix_name_ip_resolver.py hostname-to-ip SWITCH_QUERY
python zabbix_name_ip_resolver.py ip-to-hostname 10.1.1.10
python zabbix_name_ip_resolver.py search PARTIAL_NAME
```

## Troubleshooting

- `Required setting ... is missing`: check `.env` variable names and values.
- `Unable to auto-match L3 ...`: provide `--l3` explicitly.
- `Unable to discover L3 trace MAC on VLAN 111`: verify L3 MAC-table output and VLAN visibility on that device.
- `Vendor driver ... cannot ...`: platform support for that operation is not implemented for the selected vendor.
- Telnet authentication/session errors: verify credentials, access ACLs, and session limits.
