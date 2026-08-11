import sys
import os
import subprocess

# ===== PYTHON LOCATION =====
print(f"Python executable : {sys.executable}")
print(f"Python version    : {sys.version.split()[0]}")

# ===== AUTO-INSTALL DEPENDENCIES =====
REQUIRED_PACKAGES = ["netmiko"]

def install_if_missing(packages):
    import importlib
    pkg_map = {"netmiko": "netmiko"}
    for pkg in packages:
        module = pkg_map.get(pkg, pkg)
        try:
            importlib.import_module(module)
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

install_if_missing(REQUIRED_PACKAGES)

# ===== IMPORTS (after dependency check) =====
from netmiko import ConnectHandler
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import csv
import threading
import re
import getpass

# Load shared config
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import config

# ===== PATH SETUP =====
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, "..", ".."))
DATA_DIR = os.path.join(PROJECT_ROOT, "data")
REPORTS_DIR = os.path.join(PROJECT_ROOT, "reports", "cisco", "tacacs_server_check")
LOGS_DIR = os.path.join(PROJECT_ROOT, "logs")
os.makedirs(REPORTS_DIR, exist_ok=True)
os.makedirs(LOGS_DIR, exist_ok=True)

# ============== EDIT THESE ==============
DEVICE_FILE     = os.path.join(DATA_DIR, "devices.txt")
MAX_THREADS     = 30
CONNECT_TIMEOUT = 10

# IP we expect to find as `server-private` (or `server`) inside any
# `aaa group server tacacs+ <name>` block.
TARGET_TACACS_IP = "10.191.160.9"

# SSH credential fallback: the service account ([cisco_default] in
# credentials.ini) is tried first; if it is rejected (AUTH_FAIL), these LOCAL
# accounts are tried in order - one at a time - until one authenticates.
# Each entry is a section in credentials.ini, same convention used by
# cisco_detect_device_os.py, cisco_tacacs_validate.py and
# cisco_tacacs_newserver_test.py:
#   [cisco_local]
#   username = ...
#   password = ...
#   enable_password = ...   (optional; falls back to that account's own password)
# A section missing a username or password is skipped automatically, so you
# don't need to fill in every slot. The report shows which account actually
# logged in.
FALLBACK_PROFILES = ["cisco_local", "cisco_local2", "cisco_local3", "cisco_local4", "cisco_local5"]
# ========================================

print_lock = threading.Lock()


def safe_print(msg):
    with print_lock:
        print(msg)


def load_devices(filename):
    try:
        with open(filename, "r") as f:
            raw = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        seen = set()
        unique = []
        for host in raw:
            if host in seen:
                print(f"[WARN] Duplicate entry skipped: {host}")
            else:
                seen.add(host)
                unique.append(host)
        return unique
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")
        return []


def _try_connect(host, user, pwd, sec, device_type):
    return ConnectHandler(
        device_type=device_type, host=host, username=user, password=pwd,
        secret=sec or pwd, fast_cli=False, timeout=CONNECT_TIMEOUT,
        session_timeout=60,
    )


def detect_device_type(host, creds):
    """Try each credential set in order (service account first, then local
    fallbacks). For each credential, try cisco_xe first, then cisco_ios.
    Enters enable mode if needed (show running-config requires privileged
    exec on most images).
    Returns (conn, device_type, fail_reason, login_as).
    `creds` is a list of (username, password, secret, label)."""
    last_reason = "SSH_ERROR"
    for (user, pwd, sec, label) in creds:
        conn, last_error = None, ""
        for device_type in ["cisco_xe", "cisco_ios"]:
            try:
                conn = _try_connect(host, user, pwd, sec, device_type)
                break
            except Exception as e:
                last_error, conn = str(e), None

        if conn is None:
            err = last_error.lower()
            if any(s in err for s in ("timed out", "timeout", "connection refused", "unreachable")):
                return None, None, "TIMEOUT", ""   # network down: other creds won't help
            last_reason = "AUTH_FAIL" if any(
                s in err for s in ("authentication", "auth", "password")) else "SSH_ERROR"
            continue  # try the next credential

        try:
            if not conn.check_enable_mode():
                conn.enable()
        except Exception:
            pass

        return conn, device_type, "", label

    return None, None, last_reason, ""


# Parses output like:
#   aaa group server tacacs+ LCL-Net-Access-ISE
#    server-private 10.191.160.9 key 7 <hash>
#    server-private 10.191.232.7 key 7 <hash>
#   aaa group server tacacs+ OTHER-GROUP
#    server 10.0.0.1
GROUP_HEADER_RE = re.compile(r"^\s*aaa\s+group\s+server\s+tacacs\+\s+(\S+)", re.IGNORECASE)
SERVER_LINE_RE  = re.compile(r"^\s*server(?:-private)?\s+(\d+\.\d+\.\d+\.\d+)", re.IGNORECASE)


def parse_tacacs_groups(raw: str) -> dict[str, list[str]]:
    """Return {group_name: [server_ip, ...]} from the raw show-run output."""
    groups: dict[str, list[str]] = {}
    current = None
    for line in raw.splitlines():
        if line.strip().startswith("!"):
            # `!` is a section separator in IOS config dumps
            current = None
            continue
        m = GROUP_HEADER_RE.match(line)
        if m:
            current = m.group(1)
            groups.setdefault(current, [])
            continue
        if current is None:
            continue
        # Stop the group when we hit a non-indented line that isn't a server entry
        if line and not line.startswith(" ") and not line.startswith("\t"):
            current = None
            continue
        ms = SERVER_LINE_RE.match(line)
        if ms:
            groups[current].append(ms.group(1))
    return groups


def extract_tacacs_blocks(raw: str) -> str:
    """Pull just the verbatim `aaa group server tacacs+` header lines and their
    indented sub-lines out of a broader `sh run | sec aaa` dump."""
    out: list[str] = []
    capturing = False
    for line in raw.splitlines():
        if GROUP_HEADER_RE.match(line):
            capturing = True
            out.append(line.rstrip())
            continue
        if capturing:
            if line.startswith((" ", "\t")):
                out.append(line.rstrip())
            else:
                capturing = False
    return "\n".join(out)


# Legacy / non-grouped TACACS server definitions, which live OUTSIDE any
# `aaa group server tacacs+` block (and outside `sh run | sec aaa`):
#   tacacs-server host 10.191.160.9 key 7 <hash>        <- old IOS / NX-OS global
#   tacacs server LCL-Net-Access                        <- IOS 15+/XE named block
#    address ipv4 10.191.160.9
#    key 7 <hash>
TACACS_HOST_RE       = re.compile(r"^\s*tacacs-server\s+host\s+(\d+\.\d+\.\d+\.\d+)", re.IGNORECASE)
TACACS_SERVER_HDR_RE = re.compile(r"^\s*tacacs\s+server\s+\S+", re.IGNORECASE)
ADDRESS_IPV4_RE      = re.compile(r"^\s*address\s+ipv4\s+(\d+\.\d+\.\d+\.\d+)", re.IGNORECASE)


def parse_legacy_tacacs(raw: str) -> list[str]:
    """Return server IPs from legacy global `tacacs-server host <ip>` lines and
    modern `tacacs server <name>` / `address ipv4 <ip>` blocks. The `address
    ipv4` match is gated on a preceding `tacacs server` header so RADIUS server
    blocks (which also use `address ipv4`) are not picked up."""
    ips: list[str] = []
    in_tacacs_server = False
    for line in raw.splitlines():
        m = TACACS_HOST_RE.match(line)
        if m:
            ips.append(m.group(1))
            in_tacacs_server = False
            continue
        if TACACS_SERVER_HDR_RE.match(line):
            in_tacacs_server = True
            continue
        if line and not line.startswith((" ", "\t")):
            in_tacacs_server = False
        if in_tacacs_server:
            ma = ADDRESS_IPV4_RE.match(line)
            if ma:
                ips.append(ma.group(1))
    seen: set[str] = set()
    return [ip for ip in ips if not (ip in seen or seen.add(ip))]


def extract_legacy_blocks(raw: str) -> str:
    """Verbatim `tacacs-server host` lines and `tacacs server <name>` blocks
    (excludes `aaa group server tacacs+` blocks, which are captured separately)."""
    out: list[str] = []
    capturing = False
    for line in raw.splitlines():
        if TACACS_HOST_RE.match(line):
            out.append(line.rstrip())
            capturing = False
            continue
        if TACACS_SERVER_HDR_RE.match(line):
            out.append(line.rstrip())
            capturing = True
            continue
        if capturing and line.startswith((" ", "\t")):
            out.append(line.rstrip())
        elif line and not line.startswith((" ", "\t")):
            capturing = False
    return "\n".join(out)


# Synthetic group name used to report servers found via the legacy/global
# `tacacs-server host` / `tacacs server` config (i.e. the implicit `group tacacs+`).
LEGACY_GROUP_NAME = "(global/named tacacs-server)"


def classify(groups: dict[str, list[str]], target_ip: str) -> tuple[str, str, list[str]]:
    """Return (status, detail, matching_group_names)."""
    if not groups:
        return ("NO_TACACS_GROUP",
                "No TACACS server config found (no 'aaa group server tacacs+', "
                "'tacacs-server host', or 'tacacs server' on device).",
                [])
    matching = [g for g, ips in groups.items() if target_ip in ips]
    if matching:
        return ("CONFIGURED",
                f"{target_ip} present in group(s): {', '.join(matching)}",
                matching)
    all_ips = sorted({ip for ips in groups.values() for ip in ips})
    return ("NOT_CONFIGURED",
            f"{target_ip} NOT found. Servers seen: {', '.join(all_ips) if all_ips else 'none'}",
            [])


def check_device(host, creds, target_ip):
    device_start = datetime.now()

    def _result(hostname, device_type, login_status, check_status, detail,
                groups_seen, matching_groups, raw_output, aaa_config="", login_as="-"):
        duration = round((datetime.now() - device_start).total_seconds(), 1)
        return {
            "host": host,
            "hostname": hostname,
            "device_type": device_type,
            "login_status": login_status,
            "login_as": login_as or "-",
            "check_status": check_status,
            "detail": detail,
            "groups_seen": groups_seen,
            "matching_groups": matching_groups,
            "raw_output": raw_output,
            "aaa_config": aaa_config,
            "duration_s": duration,
            "tested_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }

    login_as = "-"
    try:
        safe_print(f"\n[START] Connecting to {host}...")
        net_connect, device_type, fail_reason, login_as = detect_device_type(host, creds)
        if net_connect is None:
            safe_print(f"[{fail_reason}]  {host} - Could not connect.")
            return _result("N/A", "N/A", fail_reason, "N/A",
                           f"SSH failed: {fail_reason}", "", "", "", login_as=login_as)

        hostname = net_connect.find_prompt().replace("#", "").strip()
        safe_print(f"[CONN]  {hostname} ({host}) [{device_type}] - Login: OK as {login_as}")

        net_connect.send_command("terminal length 0", read_timeout=10)
        # `sh run | sec aaa` is valid on both IOS-XE and NX-OS and returns the
        # tacacs+ server groups plus how they're referenced by auth/authz/acct.
        # (The narrower `| section aaa group server tacacs+` is invalid on NX-OS.)
        aaa_config = net_connect.send_command(
            "show running-config | section aaa",
            read_timeout=30,
        )
        # Fallback for images that don't support `| section`
        if (not aaa_config or "invalid" in aaa_config.lower()
                or "ambiguous" in aaa_config.lower()):
            aaa_config = net_connect.send_command(
                "show running-config aaa",
                read_timeout=30,
            )

        # Legacy/global TACACS servers live OUTSIDE the aaa section
        # (`tacacs-server host ...` and `tacacs server <name>` blocks), so grab
        # them too. `| section tacacs` is valid on IOS-XE and NX-OS.
        tacacs_raw = net_connect.send_command(
            "show running-config | section tacacs",
            read_timeout=30,
        )
        if (not tacacs_raw or "invalid" in tacacs_raw.lower()
                or "ambiguous" in tacacs_raw.lower()):
            tacacs_raw = net_connect.send_command(
                "show running-config | include tacacs",
                read_timeout=30,
            )

        net_connect.disconnect()

        groups = parse_tacacs_groups(aaa_config or "")
        # Merge legacy/named servers in as a synthetic group so the target check
        # and reporting cover devices that use the implicit `group tacacs+`.
        legacy_ips = parse_legacy_tacacs(tacacs_raw or "")
        if legacy_ips:
            groups[LEGACY_GROUP_NAME] = legacy_ips

        status, detail, matching = classify(groups, target_ip)
        groups_seen = "; ".join(f"{g}=[{','.join(ips) if ips else '-'}]"
                                 for g, ips in groups.items()) or "none"
        # "Raw Output" column = verbatim tacacs+ group blocks + legacy/named blocks.
        raw = "\n".join(b for b in (
            extract_tacacs_blocks(aaa_config or ""),
            extract_legacy_blocks(tacacs_raw or ""),
        ) if b)

        safe_print(f"  [{hostname}] {status} | {detail}")

        return _result(hostname, device_type, "OK", status, detail,
                       groups_seen, ",".join(matching), raw, aaa_config or "", login_as=login_as)

    except Exception as e:
        safe_print(f"[FAIL]  {host} - {e}")
        return _result("N/A", "N/A", "SSH_ERROR", "N/A", str(e), "", "", "", login_as=login_as)


def _prompt_if_empty(label, stored, secret=False):
    if stored:
        return stored
    while True:
        val = (getpass.getpass if secret else input)(f"{label}: ").strip()
        if val:
            return val
        print(f"  [!] {label} cannot be empty.")


def main():
    print("=" * 45)
    username = _prompt_if_empty("SSH Username", config.get_cred('cisco_default', 'username'))
    password = _prompt_if_empty("SSH Password", config.get_cred('cisco_default', 'password'), secret=True)
    secret    = config.get_cred('cisco_default', 'enable_password')
    print("=" * 45)

    # SSH credential chain: service account first, then local fallbacks.
    creds = [(username, password, secret, "cisco_svc")]
    for prof in FALLBACK_PROFILES:
        p_pass = config.get_cred(prof, 'password')
        if not p_pass:
            continue
        p_user = config.get_cred(prof, 'username') or prof
        p_secret = config.get_cred(prof, 'enable_password') or p_pass
        creds.append((p_user, p_pass, p_secret, prof))

    devices = load_devices(DEVICE_FILE)
    if not devices:
        print("No devices loaded. Exiting.")
        return

    print(f"Loaded {len(devices)} devices from '{DEVICE_FILE}'")
    print(f"Target TACACS IP : {TARGET_TACACS_IP}")
    print(f"Login creds      : {' -> '.join(c[3] for c in creds)}")
    print(f"Threads          : {MAX_THREADS}\n")

    start_time = datetime.now()
    timestamp = start_time.strftime("%Y%m%d_%H%M%S")
    csv_file = os.path.join(REPORTS_DIR, f"tacacs_server_check_{timestamp}.csv")
    log_file = os.path.join(LOGS_DIR,    f"tacacs_server_check_{timestamp}.txt")

    results = []
    total = len(devices)
    completed = 0
    login_counts: dict[str, int] = {}
    check_counts: dict[str, int] = {}

    def print_progress():
        bar_filled = int((completed / total) * 30)
        bar = "#" * bar_filled + "-" * (30 - bar_filled)
        print(
            f"\n  PROGRESS [{bar}] {completed}/{total} | "
            f"Login OK:{login_counts.get('OK', 0)}  "
            f"Timeout:{login_counts.get('TIMEOUT', 0)}  "
            f"AuthFail:{login_counts.get('AUTH_FAIL', 0)}  "
            f"SSHErr:{login_counts.get('SSH_ERROR', 0)} | "
            f"CONFIGURED:{check_counts.get('CONFIGURED', 0)}  "
            f"NOT_CONFIGURED:{check_counts.get('NOT_CONFIGURED', 0)}  "
            f"NO_GROUP:{check_counts.get('NO_TACACS_GROUP', 0)}\n",
            flush=True,
        )

    try:
        with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            future_to_host = {
                executor.submit(check_device, host, creds, TARGET_TACACS_IP): host
                for host in devices
            }
            for future in as_completed(future_to_host):
                result = future.result()
                results.append(result)
                completed += 1
                login_counts[result["login_status"]] = login_counts.get(result["login_status"], 0) + 1
                check_counts[result["check_status"]] = check_counts.get(result["check_status"], 0) + 1
                print_progress()
    except KeyboardInterrupt:
        print(f"\n\n[!] Interrupted by user. Saving {len(results)} result(s) collected so far...")

    device_order = {host: idx for idx, host in enumerate(devices)}
    results.sort(key=lambda r: device_order.get(r["host"], 999999))

    # CSV
    with open(csv_file, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f)
        writer.writerow([
            "#", "Host IP", "Hostname", "Device Type",
            "Login Status", "Login As", "Check Status", "Target IP",
            "Matching Groups", "Groups Seen", "Detail",
            "Duration (s)", "Tested At", "Raw Output (truncated)",
            "AAA Config (sh run | sec aaa)",
        ])
        for idx, r in enumerate(results, 1):
            raw_single = " | ".join(
                line.strip() for line in r["raw_output"].splitlines() if line.strip()
            )[:200]
            aaa_single = " | ".join(
                line.strip() for line in r["aaa_config"].splitlines() if line.strip()
            )
            writer.writerow([
                idx, r["host"], r["hostname"], r["device_type"],
                r["login_status"], r["login_as"], r["check_status"], TARGET_TACACS_IP,
                r["matching_groups"], r["groups_seen"], r["detail"],
                r["duration_s"], r["tested_at"], raw_single, aaa_single,
            ])
        writer.writerow([])
        writer.writerow([
            "SUMMARY", f"{len(results)} devices", "", "",
            f"Login OK: {login_counts.get('OK', 0)} | "
            f"Timeout: {login_counts.get('TIMEOUT', 0)} | "
            f"Auth Fail: {login_counts.get('AUTH_FAIL', 0)} | "
            f"SSH Err: {login_counts.get('SSH_ERROR', 0)}",
            "",
            f"CONFIGURED: {check_counts.get('CONFIGURED', 0)} | "
            f"NOT_CONFIGURED: {check_counts.get('NOT_CONFIGURED', 0)} | "
            f"NO_TACACS_GROUP: {check_counts.get('NO_TACACS_GROUP', 0)}",
            TARGET_TACACS_IP, "", "", "",
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "",
        ])
    print(f"\nCSV saved to: {csv_file}")

    # Detailed log
    with open(log_file, "w") as f:
        f.write(f"TACACS Server Check Report\n")
        f.write(f"Target IP  : {TARGET_TACACS_IP}\n")
        f.write(f"Run Time   : {start_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"{'='*70}\n\n")
        for idx, r in enumerate(results, 1):
            f.write(
                f"[{idx}] {r['host']} | {r['hostname']} | {r['device_type']} | "
                f"Login: {r['login_status']} as {r['login_as']} | Check: {r['check_status']} | "
                f"Duration: {r['duration_s']}s | Tested: {r['tested_at']}\n"
            )
            f.write(f"     Detail        : {r['detail']}\n")
            f.write(f"     Groups Seen   : {r['groups_seen']}\n")
            if r["matching_groups"]:
                f.write(f"     Matched Groups: {r['matching_groups']}\n")
            if r["raw_output"]:
                f.write(f"     Raw Output    :\n")
                for line in r["raw_output"].splitlines():
                    f.write(f"       {line}\n")
            if r["aaa_config"]:
                f.write(f"     AAA Config (sh run | sec aaa):\n")
                for line in r["aaa_config"].splitlines():
                    f.write(f"       {line}\n")
            f.write(f"{'-'*70}\n\n")
    print(f"Log saved to: {log_file}")

    elapsed = datetime.now() - start_time
    durations = [r["duration_s"] for r in results if r["login_status"] == "OK"]
    avg_dur = round(sum(durations) / len(durations), 1) if durations else 0
    max_dur = max(durations) if durations else 0

    print(f"\n{'='*55}")
    print(f"  --- Device Login ---")
    print(f"  OK                                   : {login_counts.get('OK', 0)}")
    print(f"  Timeout (unreachable)                : {login_counts.get('TIMEOUT', 0)}")
    print(f"  SSH Auth Fail                        : {login_counts.get('AUTH_FAIL', 0)}")
    print(f"  SSH Error                            : {login_counts.get('SSH_ERROR', 0)}")
    print(f"  --- TACACS Server Check (target {TARGET_TACACS_IP}) ---")
    print(f"  CONFIGURED                           : {check_counts.get('CONFIGURED', 0)}")
    print(f"  NOT CONFIGURED                       : {check_counts.get('NOT_CONFIGURED', 0)}")
    print(f"  NO TACACS GROUP                      : {check_counts.get('NO_TACACS_GROUP', 0)}")
    print(f"  --- Timing ---")
    print(f"  Avg per device                       : {avg_dur}s")
    print(f"  Slowest device                       : {max_dur}s")
    print(f"{'='*55}")
    print(f"Total devices : {len(results)} | Total time : {elapsed}")


if __name__ == "__main__":
    main()
