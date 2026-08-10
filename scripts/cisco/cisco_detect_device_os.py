
#!/usr/bin/env python3
"""
Cisco Device Type Detector
Automatically detects device OS type (IOS, IOS-XE, NX-OS, IOS-XR, ASA, etc.)
and device family (Catalyst, Nexus, ASR/ISR, ASA, ...).
"""

import sys
import os
import subprocess
import importlib

# ===== AUTO-INSTALL DEPENDENCIES =====
def install_if_missing(packages):
    for pkg in packages:
        try:
            importlib.import_module(pkg)
        except ImportError:
            print(f"[SETUP] '{pkg}' not found. Installing...")
            result = subprocess.run(
                [sys.executable, "-m", "pip", "install", pkg],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                print(f"[SETUP] '{pkg}' installed successfully.")
            else:
                print(f"[SETUP] ERROR installing '{pkg}':\n{result.stderr}")
                sys.exit(1)

install_if_missing(["netmiko"])

# ── Load shared config ─────────────────────────────────────────
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import config
print(f"[DEBUG] config module loaded from: {getattr(config, '__file__', 'unknown')}")

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException
import re
import csv
import io
import json
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# ===== PATH SETUP =====
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, "..", ".."))
DATA_DIR = os.path.join(PROJECT_ROOT, "data")
REPORTS_DIR = os.path.join(PROJECT_ROOT, "reports", "cisco", "device_discovery")
os.makedirs(REPORTS_DIR, exist_ok=True)

# ===== CONFIGURATION =====
# Global defaults (used when per-device credentials are not provided in devices.txt)
USERNAME        = config.get_cred('cisco_default', 'username',        'araung')
PASSWORD        = config.get_cred('cisco_default', 'password')
ENABLE_PASSWORD = config.get_cred('cisco_default', 'enable_password')

# Local-user fallback, tried (in order) only if the service account fails to
# authenticate. Multiple local accounts are supported via numbered sections
# in credentials.ini: [cisco_local], [cisco_local2], [cisco_local3], ...
# Any section missing a username or password is skipped.
LOCAL_ACCOUNT_SECTIONS = ['cisco_local', 'cisco_local2', 'cisco_local3', 'cisco_local4', 'cisco_local5']


def _load_local_accounts():
    accounts = []
    for section in LOCAL_ACCOUNT_SECTIONS:
        local_username = config.get_cred(section, 'username')
        local_password = config.get_cred(section, 'password')
        if local_username and local_password:
            accounts.append({
                'label': f'local user [{section}]',
                'username': local_username,
                'password': local_password,
                'enable': config.get_cred(section, 'enable_password'),
            })
    return accounts


LOCAL_ACCOUNTS = _load_local_accounts()

print(f"[DEBUG] cisco_default username came from config: {config.get_cred('cisco_default', 'username') is not None} "
      f"(resolved username='{USERNAME}')")
print(f"[DEBUG] cisco_default password came from config: {config.get_cred('cisco_default', 'password') is not None}")
print(f"[DEBUG] local-user fallback accounts configured: {len(LOCAL_ACCOUNTS)}")

# Path to the device list file (one IP per line, or CSV: ip,username,password,enable)
DEVICE_LIST_FILE = os.path.join(DATA_DIR, "devices.txt")

# Timeout for connection attempts
TIMEOUT = 15

# How many devices to probe concurrently. SSH connects are mostly spent
# waiting on the network/device, so threads give a large speedup with
# little risk. Keep this modest so we don't hammer a shared AAA/TACACS
# server with a burst of simultaneous logins.
MAX_WORKERS = 8

# Netmiko device_type values to try, covering IOS, IOS-XE (incl. Catalyst),
# NX-OS (Nexus) and IOS-XR platforms, plus ASA firewalls.
DEVICE_TYPES_TO_TRY = [
    'cisco_ios',   # IOS and IOS-XE (Catalyst switches, ISR routers, etc.)
    'cisco_xe',    # IOS-XE (alternative driver)
    'cisco_nxos',  # Nexus switches
    'cisco_xr',    # IOS-XR (ASR9k, NCS)
    'cisco_asa',   # ASA firewalls
]
# ========================


def load_devices_from_file(path: str):
    """
    Load devices from a text file.
    Supported formats per line:
      - "ip"
      - "ip,username,password,enable"
    Lines starting with '#' or blank lines are ignored.

    Returns:
        list[dict]: Each dict contains:
          {'ip': str, 'username': str, 'password': str, 'enable': str or None}
    """
    devices = []
    if not os.path.exists(path):
        raise FileNotFoundError(f"Device list file not found: {path}")

    with open(path, "r") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            parts = [p.strip() for p in line.split(",")]
            if len(parts) == 1:
                ip = parts[0]
                devices.append({
                    "ip": ip,
                    "username": USERNAME,
                    "password": PASSWORD,
                    "enable": ENABLE_PASSWORD if ENABLE_PASSWORD else None
                })
            elif len(parts) >= 3:
                # ip,username,password[,enable]
                ip, u, p = parts[0], parts[1], parts[2]
                enable = parts[3] if len(parts) >= 4 and parts[3] else None
                devices.append({
                    "ip": ip,
                    "username": u or USERNAME,
                    "password": p or PASSWORD,
                    "enable": enable
                })
            else:
                # Invalid line; skip but warn
                print(f"⚠️  Skipping invalid line in {path}: {line}")

    return devices


def build_credential_sets(username, password, enable_password):
    """
    Build the ordered list of credential sets to attempt for a device:
      1. The device's own/service-account credentials (from devices.txt
         or the cisco_default config section).
      2. Each configured local-user fallback account, in the order defined
         by LOCAL_ACCOUNT_SECTIONS, tried one at a time only if the
         previous credential set failed to authenticate.
    """
    credential_sets = [{
        'label': 'service account',
        'username': username,
        'password': password,
        'enable': enable_password,
    }]

    for account in LOCAL_ACCOUNTS:
        credential_sets.append({
            'label': account['label'],
            'username': account['username'],
            'password': account['password'],
            'enable': account['enable'] or enable_password,
        })

    return credential_sets


def detect_device_type(device_ip, username, password, enable_password=None):
    """
    Detect the device type by trying different connection methods
    and analyzing 'show version' output. Tries the service-account
    credentials first; if those fail authentication, automatically
    falls back to the local-user credentials (when configured).

    Args:
        device_ip: IP address of the device
        username: SSH username (service account)
        password: SSH password (service account)
        enable_password: Enable password (optional)
    Returns:
        tuple: (success: bool, device_type: str, device_info: dict, log_text: str)
    """
    out = io.StringIO()
    print(f"Detecting device type for {device_ip}...", file=out)

    credential_sets = build_credential_sets(username, password, enable_password)
    last_error = "Unable to detect device type"

    for cred_index, cred in enumerate(credential_sets):
        print(f"  Trying {cred['label']} ({cred['username']})...", end=" ", file=out)
        for device_type in DEVICE_TYPES_TO_TRY:
            try:
                device_config = {
                    'device_type': device_type,
                    'host': device_ip,
                    'username': cred['username'],
                    'password': cred['password'],
                    'timeout': TIMEOUT,
                    'session_log': None,
                }
                if cred['enable']:
                    device_config['secret'] = cred['enable']

                connection = ConnectHandler(**device_config)

                # Try to enter enable mode - Netmiko will skip if already in enable mode
                try:
                    connection.enable()
                except Exception:
                    # Device may not support enable mode or already in enable
                    pass

                # Get show version output
                version_output = connection.send_command("show version", read_timeout=30)
                hostname = connection.find_prompt().strip('#').strip('>')
                connection.disconnect()

                # Analyze the output to determine actual device type and model
                device_info = analyze_version_output(version_output, hostname)
                device_info['detected_type'] = device_type
                device_info['ip'] = device_ip
                device_info['credential_used'] = cred['label']
                label_suffix = f" [{cred['label']}]" if cred_index > 0 else ""
                print(f"✓ Detected: {device_info['os_type']} ({device_info['model']}){label_suffix}", file=out)
                return True, device_type, device_info, out.getvalue()

            except NetmikoAuthenticationException as exc:
                # Wrong credentials for this device_type/credential set;
                # stop trying other device_types with the same credentials
                # and fall through to the next credential set, if any.
                # NOTE: Netmiko also raises this exception for some
                # non-credential failures (e.g. a login banner delaying
                # the prompt, or an SSH kex/cipher the device doesn't
                # support) - the original exception text below is the
                # real reason, not necessarily a bad password.
                detail = str(exc).strip().splitlines()[-1] if str(exc).strip() else "no detail from Netmiko"
                last_error = f"Authentication failed ({cred['label']}): {detail}"
                print(f"✗ {last_error}", file=out)
                break
            except NetmikoTimeoutException as exc:
                # Device unreachable - no point retrying with other
                # credentials or device_types.
                last_error = f"Connection timed out: {exc}"
                print(f"✗ {last_error}", file=out)
                return False, None, _failed_device_info(device_ip, last_error), out.getvalue()
            except Exception as exc:
                # Try next device_type with the same credentials
                last_error = str(exc) or "Unable to detect device type"
                continue
        else:
            # Inner for-loop finished without a `break` (every device_type
            # raised something other than an auth exception) - report it
            # and move on to the next credential set, if any.
            print(f"✗ {last_error}", file=out)

    # Every credential set / device_type combination failed
    return False, None, _failed_device_info(device_ip, last_error), out.getvalue()


def _failed_device_info(device_ip, error_msg):
    return {
        'ip': device_ip,
        'hostname': 'Unknown',
        'os_type': 'Unknown',
        'device_family': 'Unknown',
        'detected_type': None,
        'model': 'Unknown',
        'version': 'Unknown',
        'version_line': '',
        'serial': 'Unknown',
        'uptime': 'Unknown',
        'credential_used': 'none',
        'error': error_msg
    }


def analyze_version_output(version_output, hostname):
    """
    Analyze 'show version' output to determine OS type, device family and model.
    """
    device_info = {
        'hostname': hostname,
        'os_type': 'Unknown',
        'device_family': 'Unknown',
        'model': 'Unknown',
        'version': 'Unknown',
        'serial': 'Unknown',
        'uptime': 'Unknown',
        'version_line': '',  # Store the matched line for debugging
    }

    version_lower = version_output.lower()

    # Detect OS Type
    if 'nx-os' in version_lower or 'nexus' in version_lower:
        device_info['os_type'] = 'NX-OS'
    elif 'ios-xr' in version_lower or 'iosxr' in version_lower:
        device_info['os_type'] = 'IOS-XR'
    elif 'ios xe' in version_lower or 'ios-xe' in version_lower:
        device_info['os_type'] = 'IOS-XE'
    elif 'cisco ios software' in version_lower:
        device_info['os_type'] = 'IOS'
    elif 'adaptive security appliance' in version_lower or 'cisco asa' in version_lower:
        device_info['os_type'] = 'ASA'

    # Extract Model
    model_patterns = [
        r'cisco\s+([A-Z0-9\-]+)\s+(?:\(.+?\)\s+)?processor',
        r'cisco\s+(nexus\s*\d+)',
        r'hardware:\s+(\S+)',
        r'cisco\s+(\S+)\s+(.+?)\s+processor',
        r'Model\s+number\s+:\s+(\S+)',
    ]
    for pattern in model_patterns:
        match = re.search(pattern, version_output, re.IGNORECASE)
        if match:
            device_info['model'] = match.group(1)
            break

    # Detect device family from model / keywords (Catalyst, Nexus, ASR/ISR, ASA)
    device_info['device_family'] = detect_device_family(version_lower, device_info['model'])

    # Extract Version
    version_patterns = [
        (r'^\s*NXOS:\s+version\s+([0-9]+\.[0-9]+(?:\([0-9]+\)[^\s,\[\]]*)?)', 'NX-OS'),
        (r'Version\s+([0-9]+\.[0-9]+\([^\)]+\)[^\s,]*)', 'IOS'),
        (r'Version\s+([0-9]+\.[0-9]+[^\s,]+)', 'Generic'),
        (r'System\s+image\s+file\s+is.*?Version\s+([0-9]+\.[0-9]+[^\s,]+)', 'Image'),
    ]
    for pattern, pattern_type in version_patterns:
        if pattern_type == 'NX-OS':
            match = re.search(pattern, version_output, re.IGNORECASE | re.MULTILINE)
            if match:
                device_info['version'] = match.group(1)
                for line in version_output.split('\n'):
                    if re.search(pattern, line, re.IGNORECASE):
                        device_info['version_line'] = line.strip()
                        break
                break
        else:
            lines = version_output.split('\n')
            for line in lines:
                if re.search(r'BIOS.*version', line, re.IGNORECASE):
                    continue
                if re.search(r'GPL.*version|LGPL.*Version', line, re.IGNORECASE):
                    continue
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    device_info['version'] = match.group(1)
                    device_info['version_line'] = line.strip()
                    break
            if device_info['version'] != 'Unknown':
                break

    # Extract Serial Number
    serial_patterns = [
        r'Processor board ID\s+(\S+)',
        r'System serial number\s*:\s*(\S+)',
    ]
    for pattern in serial_patterns:
        match = re.search(pattern, version_output, re.IGNORECASE)
        if match:
            device_info['serial'] = match.group(1)
            break

    # Extract Uptime
    uptime_patterns = [
        r'uptime is\s+(.+?)(?:\n|\r)',
        r'Kernel uptime is\s+(.+?)(?:\n|\r)',
    ]
    for pattern in uptime_patterns:
        match = re.search(pattern, version_output, re.IGNORECASE)
        if match:
            device_info['uptime'] = match.group(1).strip()
            break

    return device_info


def detect_device_family(version_lower, model):
    """
    Classify the device into a broad hardware family based on the
    'show version' text and the extracted model number.
    """
    model_upper = (model or '').upper()

    if 'nexus' in version_lower or re.match(r'^N\d', model_upper):
        return 'Nexus'
    if model_upper.startswith('WS-C') or model_upper.startswith('C9') or model_upper.startswith('C3') \
            or model_upper.startswith('C2') or 'catalyst' in version_lower:
        return 'Catalyst'
    if model_upper.startswith('ASR'):
        return 'ASR'
    if model_upper.startswith('ISR') or model_upper.startswith('C8'):
        return 'ISR'
    if model_upper.startswith('NCS'):
        return 'NCS'
    if 'adaptive security appliance' in version_lower or 'cisco asa' in version_lower or model_upper.startswith('ASA'):
        return 'ASA'
    return 'Unknown'


def save_results_csv(results, filename='device_types.csv'):
    if not results:
        return
    fieldnames = ['ip', 'hostname', 'os_type', 'device_family', 'detected_type', 'model',
                  'version', 'version_line', 'serial', 'uptime', 'credential_used', 'status']
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames, extrasaction='ignore')
        writer.writeheader()
        for result in results:
            result['status'] = 'success' if 'error' not in result else 'failed'
            if 'version_line' not in result:
                result['version_line'] = ''
            writer.writerow(result)
    print(f"\n✓ Results saved to: {filename}")


def save_results_json(results, filename='device_types.json'):
    output = {
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'total_devices': len(results),
        'devices': results
    }
    with open(filename, 'w') as jsonfile:
        json.dump(output, jsonfile, indent=2)
    print(f"✓ Results saved to: {filename}")


def generate_device_list_for_collector(results, filename='device_list.py'):
    with open(filename, 'w') as f:
        f.write("# Auto-generated device list - Copy to cisco_ssh_collector.py\n")
        f.write("# Generated: " + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + "\n\n")
        f.write("DEVICES = [\n")
        for result in results:
            if 'error' not in result and result.get('detected_type'):
                ip = result['ip']
                device_type = result['detected_type']
                hostname = result.get('hostname', 'Unknown')
                f.write(f'    {{"ip": "{ip}", "type": "{device_type}"}},  # {hostname}\n')
        f.write("]\n")
    print(f"✓ Device list generated: {filename}")


def main():
    print(f"\n{'='*80}")
    print("Cisco Device Type Detector")
    print(f"{'='*80}\n")

    if not PASSWORD:
        print("✗ ERROR: cisco_default password could not be retrieved from config.py "
              "(config.get_cred('cisco_default', 'password') returned nothing).")
        print("  This has been observed to be intermittent - the same lookup can succeed on one")
        print("  run and fail on the next - which points to a flaky credential source in your")
        print("  config.py (vault/API/Credential Manager lookup) rather than a wrong password.")
        print("  Refusing to proceed with an empty password to avoid a false 'auth failed' /")
        print("  'no authentication methods available' error and unnecessary device login attempts.")
        print("  Fix config.py's credential retrieval, or re-run once it succeeds, then retry.\n")
        sys.exit(1)

    # Load devices from file
    devices = load_devices_from_file(DEVICE_LIST_FILE)
    print(f"Total devices to detect: {len(devices)}\n")

    if LOCAL_ACCOUNTS:
        names = ', '.join(account['username'] for account in LOCAL_ACCOUNTS)
        print(f"Local-user fallback is enabled for {len(LOCAL_ACCOUNTS)} account(s): {names}\n")
    else:
        print("Local-user fallback is not configured "
              "(add [cisco_local], [cisco_local2], ... to credentials.ini to enable it).\n")

    all_results = []
    successful = []
    failed = []
    print_lock = threading.Lock()
    worker_count = min(MAX_WORKERS, len(devices)) or 1
    print(f"Probing devices concurrently with {worker_count} worker(s)...\n")

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        future_to_dev = {
            executor.submit(
                detect_device_type, dev['ip'], dev['username'], dev['password'], dev.get('enable')
            ): dev
            for dev in devices
        }
        for future in as_completed(future_to_dev):
            success, device_type, device_info, log_text = future.result()
            with print_lock:
                print(f"{'─'*80}")
                print(log_text, end="")
            all_results.append(device_info)
            (successful if success else failed).append(device_info)

    # Keep output deterministic regardless of which device finished first
    all_results.sort(key=lambda d: d.get('ip', ''))
    successful.sort(key=lambda d: d.get('ip', ''))
    failed.sort(key=lambda d: d.get('ip', ''))

    # Print summary
    print(f"\n\n{'='*80}")
    print("DETECTION SUMMARY")
    print(f"{'='*80}")
    print(f"Total devices: {len(devices)}")
    print(f"Successfully detected: {len(successful)}")
    print(f"Failed: {len(failed)}")

    if successful:
        print(f"\n✓ Successfully detected devices:")
        print(f"{'IP':<15} {'Hostname':<20} {'OS Type':<10} {'Family':<10} {'Version':<15} {'Model':<20}")
        print(f"{'-'*100}")
        for device in successful:
            print(f"{device['ip']:<15} {device['hostname']:<20} "
                  f"{device['os_type']:<10} {device['device_family']:<10} "
                  f"{device['version']:<15} {device['model']:<20}")

    if failed:
        print(f"\n✗ Failed detections:")
        for device in failed:
            print(f" - {device['ip']}: {device.get('error', 'Unknown error')}")

    # Save results
    print(f"\n{'='*80}")
    print("SAVING RESULTS")
    print(f"{'='*80}")
    save_results_csv(all_results, os.path.join(REPORTS_DIR, 'device_types.csv'))
    save_results_json(all_results, os.path.join(REPORTS_DIR, 'device_types.json'))
    generate_device_list_for_collector(successful, os.path.join(REPORTS_DIR, 'device_list.py'))
    print(f"\n{'='*80}\n")


if __name__ == "__main__":
    main()
