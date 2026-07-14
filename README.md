# VLAN Tunnel Automation Tool

This project is a CLI tool for tracing VLAN paths across mixed-vendor switches and applying VLAN/tagging changes hop-by-hop.

## What It Does

- Resolves switches by name/alias/IP via Zabbix.
- Probes switch connectivity and captures full Telnet session logs.
- Looks up MAC addresses on supported vendors.
- Finds a free VLAN on L3 switches using vendor-specific rules.
- Builds a dry-run VLAN path plan (`plan`).
- Applies VLAN/tagging changes live (`deploy`).

Supported vendor drivers in current code:

- `cisco_ios`
- `snr`
- `snr_s2970` (`SNR-S2970*` series)
- `snr_s5xxx`
- `eltex_mes`
- `arista`
- `bdcom_gpon` (`bdcom.gp3600` / `bdcom.gpon`, creates GPON ONU VLAN profiles)
- `fd160`
- `GR-EP-OLT1-4` local auth only
- `GR-EP-OLT2-8-2AC`, VLAN 111 MAC tracing
- `generic_telnet` (fallback)

## Requirements

- Python 3.10+
- Network access to target switches over Telnet
- Zabbix API access if Zabbix resolution is enabled

## Installation

```powershell
cd C:\path\to\repo
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Configuration

Copy .env.example to .env and fill in with your credentials.
Copy config.example.yaml to config.yaml and fill in with your working constraints.

### 1) `.env`

Set credentials and API settings in `.env`:

```dotenv
VLAN_TELNET_USERNAME=your_username
VLAN_TELNET_PASSWORD=your_password
VLAN_TELNET_SECRET=your_enable_secret

# Optional vendor-local override for GR-EP-OLT1-4.
# Username defaults to root when omitted; password is required for this vendor.
# VLAN_GR_EP_OLT1_TELNET_USERNAME=root
# VLAN_GR_EP_OLT1_TELNET_PASSWORD=local_password

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
  username_env: TELNET_USERNAME
  password_env: TELNET_PASSWORD
  secret_env: TELNET_SECRET
  port: 23
  timeout_seconds: 20
  global_delay_factor: 1.5

zabbix:
  enabled: true
  url_env: ZABBIX_URL
  api_token_env: ZABBIX_API_TOKEN
  username_env: ZABBIX_USERNAME
  password_env: ZABBIX_PASSWORD
  search_field: host

l3_mapping:
  overrides:
    - subnet: 10.7.101.0/24
      l3_ip: 10.1.1.1
    - subnet: 10.7.202.0/24
      l3_ip: 10.1.1.1
    - subnet: 10.7.30.0/24
      l3_ip: 10.1.1.1
    - subnet: 10.7.108.0/24
      l3_ip: 10.1.1.8

vlan_ranges:
  - start: 200
    end: 300
  - start: 1200
    end: 1300
```

Notes:

- Secrets should stay in `.env`, not hardcoded in `config.yaml`.
- If `zabbix.enabled: true`, you must provide URL plus either API token or username/password.
- `l3_mapping.overrides` is evaluated before the default L3 derivation rule.
- If multiple override subnets match, the most specific CIDR (largest prefix length) wins.

## Usage

```text
main.py [-h] [--nodebug] {resolve,probe,mac,find-vlan,plan,deploy} ...

main.py probe SWITCH [--l3 L3_SWITCH_NAME_OR_IP]
main.py find-vlan L3_SWITCH_NAME_OR_IP
main.py plan DEST_SWITCH [DEST_PORT] [--l3 L3_SWITCH] [--vlan VLAN_ID]
main.py deploy DEST_SWITCH [DEST_PORT] [--l3 L3_SWITCH] [--vlan VLAN_ID]
```

Commands:

- `resolve`: Resolve a switch name/alias/IP to the final host record the tool will use.
- `probe`: Verify switch connectivity (runs "show version")
- `mac`: Search a switch MAC table for a specific MAC and show where it is learned.
- `find-vlan`: Find the first free VLAN on the selected L3.
- `plan`: Build a dry-run hop-by-hop VLAN path plan (what would be changed, without applying).
- `deploy`: Execute the hop-by-hop VLAN path changes live on the traced switches.

| flag | what it does |
| --- | --- |
| `-h`, `--help` | Show CLI help. |
| `--nodebug` | Quiet mode: hide live switch connect/command output. Still prints chosen VLAN and the change summary. Live output is on by default. |
| `--l3 L3_SWITCH` | Manually override L3 switch selection. |
| `--vlan VLAN_ID` | Use a fixed VLAN instead of automatic free-VLAN selection in `deploy` and `plan`. |

Notes:

- `DEST_PORT` is optional for `plan`/`deploy`; if omitted, the tool asks the matched L3 switch for `show ip arp <destination IP>` and uses that MAC. Destination self-MAC discovery remains a fallback if ARP does not return a usable MAC.
- In `plan`/`deploy`, if `--vlan` is omitted the tool auto-selects a free VLAN from configured ranges.
- On OLT devices, deploy/trace aborts when downlink resolves to ONU terminal-style interfaces (`gponX/Y:Z`).

## Logs

- Session logs are written to `log_directory` (default: `logs/`).
- Filenames are generated as `<host>_YYYYMMDD_HHMMSS.log`.

## Troubleshooting

- `Required setting ... is missing`: check `.env` variable names and values.
- `Unable to auto-match L3 ...`: provide `--l3` explicitly or add in config.yaml as an override map.
- `Unable to discover L3 trace MAC on VLAN 111`: verify L3 MAC-table output and VLAN visibility on that device.
- `Vendor driver ... cannot ...`: platform support for that operation is not implemented for the selected vendor.
- Telnet authentication/session errors: verify credentials, access ACLs, and session limits.
