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
from netmiko.exceptions import (
    NetmikoAuthenticationException,
    NetmikoTimeoutException,
)
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import csv
import socket
import threading
import platform
import re

# ── Load shared config ─────────────────────────────────────────
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import config

# ===== PATH SETUP =====
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, "..", ".."))
DATA_DIR = os.path.join(PROJECT_ROOT, "data")
REPORTS_DIR = os.path.join(PROJECT_ROOT, "reports", "cisco", "image_reachability")
LOGS_DIR = os.path.join(PROJECT_ROOT, "logs")
os.makedirs(REPORTS_DIR, exist_ok=True)
os.makedirs(LOGS_DIR, exist_ok=True)

# ============== EDIT THESE ==============
DEVICE_FILE = os.path.join(DATA_DIR, "devices.txt")
USERNAME    = config.get_cred('cisco_svc', 'username', 'SVC_NMS_TACACS')
PASSWORD    = config.get_cred('cisco_svc', 'password')
MAX_THREADS = 20          # No MD5 here, so this can run much wider than the MD5 script

TARGET_IMAGE = "cat9k_lite_iosxe.17.15.03.SPA.bin"

PING_COUNT     = 2        # ICMP probes per device
PING_TIMEOUT   = 2        # seconds per probe
TCP_PORT       = 22       # SSH
TCP_TIMEOUT    = 5        # seconds for the TCP/22 handshake
SSH_TIMEOUT    = 30       # seconds for netmiko login
SKIP_SSH_IF_NO_PING = False   # True = don't attempt SSH when ICMP fails (faster, but
                              # misses devices where ICMP is filtered and SSH works)
# ========================================

print_lock = threading.Lock()


def safe_print(msg):
    with print_lock:
        print(msg)


def load_devices(filename):
    try:
        with open(filename, "r") as f:
            devices = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        return devices
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")
        return []


# ───────────────────────── LAYER 1: ICMP ─────────────────────────
def ping_host(host):
    """Return (reachable: bool, avg_rtt_ms: str). ICMP may be filtered even on
    healthy devices, so a False here is informational, not fatal."""
    is_windows = platform.system().lower() == "windows"
    if is_windows:
        cmd = ["ping", "-n", str(PING_COUNT), "-w", str(PING_TIMEOUT * 1000), host]
    else:
        cmd = ["ping", "-c", str(PING_COUNT), "-W", str(PING_TIMEOUT), host]

    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=(PING_COUNT * PING_TIMEOUT) + 5,
        )
        output = proc.stdout + proc.stderr
        reachable = proc.returncode == 0 and "unreachable" not in output.lower()

        rtt = "N/A"
        # Linux/mac: rtt min/avg/max/mdev = 1.234/2.345/3.456/0.123 ms
        m = re.search(r"=\s*[\d.]+/([\d.]+)/", output)
        if m:
            rtt = f"{float(m.group(1)):.1f}"
        else:
            # Windows: Average = 2ms
            m = re.search(r"Average\s*=\s*(\d+)ms", output)
            if m:
                rtt = f"{float(m.group(1)):.1f}"
        return reachable, rtt
    except Exception:
        return False, "N/A"


# ───────────────────────── LAYER 2: TCP/22 ─────────────────────────
def check_tcp_port(host, port=TCP_PORT, timeout=TCP_TIMEOUT):
    """Return (open: bool, banner: str). Confirms the SSH service is actually
    listening — this is what separates 'device down' from 'ACL/route problem'."""
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        banner = ""
        try:
            sock.settimeout(3)
            banner = sock.recv(128).decode(errors="ignore").strip()
        except Exception:
            pass
        return True, banner
    except Exception:
        return False, ""
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


# ───────────────────────── LAYER 3: SSH LOGIN ─────────────────────────
def detect_device_type(host, username, password):
    """Try cisco_xe first, then cisco_ios as fallback.
    Returns (net_connect, device_type, auth_state)."""
    last_state = "SSH_FAILED"
    for device_type in ["cisco_xe", "cisco_ios"]:
        try:
            device = {
                "device_type": device_type,
                "host": host,
                "username": username,
                "password": password,
                "fast_cli": False,
                "timeout": SSH_TIMEOUT,
                "session_timeout": 60,
            }
            net_connect = ConnectHandler(**device)
            output = net_connect.send_command("show version | include IOS-XE", read_timeout=15)
            if "IOS-XE" in output or "IOS XE" in output:
                return net_connect, "cisco_xe", "OK"
            return net_connect, "cisco_ios", "OK"
        except NetmikoAuthenticationException:
            # Bad creds won't improve by changing device_type — stop here.
            return None, None, "AUTH_FAILED"
        except NetmikoTimeoutException:
            last_state = "SSH_TIMEOUT"
            continue
        except Exception:
            last_state = "SSH_FAILED"
            continue
    return None, None, last_state


# ───────────────────────── STACK / FLASH HELPERS ─────────────────────────
def get_stack_members(net_connect):
    """Detect stack members and return list of switch numbers."""
    try:
        output = net_connect.send_command("show switch", read_timeout=15)
        members = []
        for line in output.splitlines():
            match = re.match(r"[\s*]*(\d+)\s+(Active|Standby|Member)", line)
            if match:
                members.append(int(match.group(1)))
        if members:
            return sorted(members)
    except Exception:
        pass
    return []


def get_running_version(net_connect):
    """Best-effort current version + model, useful context in the report."""
    version, model = "N/A", "N/A"
    try:
        output = net_connect.send_command("show version", read_timeout=30)
        m = re.search(r"Version\s+([0-9]+\.[0-9]+\.[0-9]+[A-Za-z0-9.]*)", output)
        if m:
            version = m.group(1)
        m = re.search(r"[Mm]odel [Nn]umber\s*:\s*(\S+)", output)
        if m:
            model = m.group(1)
        else:
            m = re.search(r"cisco\s+(\S+)\s+\(", output)
            if m:
                model = m.group(1)
    except Exception:
        pass
    return version, model


def bytes_to_mb(value):
    try:
        return round(int(value) / (1024 * 1024), 1)
    except Exception:
        return "N/A"


def check_image_presence(net_connect, hostname, flash_label, target_image):
    """Existence check only — no MD5, so this returns in seconds, not minutes.

    Lists the whole filesystem and searches the entry lines for the file,
    instead of running 'dir <fs><file>' and sniffing the error text. The
    per-file variant is fragile: error wording differs across IOS/IOS-XE
    releases, and any stray '% Invalid input' left in the session buffer by
    an earlier command made an image that IS on flash report as missing.
    With a full listing the file either shows up as an entry line or it
    doesn't — no error-string guessing involved."""
    result = {
        "flash": flash_label,
        "exists": False,
        "size_mb": "N/A",
        "free_mb": "N/A",
        "detail": "",
    }

    safe_print(f"  [{hostname}] Checking {flash_label} for {target_image} ...")
    try:
        dir_output = net_connect.send_command(f"dir {flash_label}", read_timeout=90)
    except Exception as e:
        result["detail"] = f"dir command failed: {e}"
        safe_print(f"  [{hostname}] {flash_label} -> {result['detail']}")
        return result

    # Free space is printed on the trailer line of dir output
    free_match = re.search(r"\((\d+)\s+bytes free\)", dir_output)
    if free_match:
        result["free_mb"] = bytes_to_mb(free_match.group(1))

    # An error on a plain 'dir <fs>' means the filesystem itself is bad
    # (wrong label, stack member gone) — report that, not "image missing".
    # Only fatal when no listing came back at all: a stray error line left
    # in the buffer by an earlier command must not discard a good listing.
    got_listing = "Directory of" in dir_output or free_match is not None
    if not got_listing and re.search(
            r"%Error|%Invalid|Invalid input|No such device", dir_output, re.IGNORECASE):
        first_err = next(
            (ln.strip() for ln in dir_output.splitlines() if ln.strip().startswith("%")),
            "filesystem error",
        )
        result["detail"] = f"Cannot list {flash_label} ({first_err})"
        safe_print(f"  [{hostname}] {flash_label} -> {result['detail']}")
        return result

    # Entry lines look like:
    #   434184  -rw-   1016954327  Aug  1 2024 12:34:56 +00:00  cat9k_lite_iosxe.17.15.03.SPA.bin
    case_mismatch = None
    for line in dir_output.splitlines():
        tokens = line.split()
        if len(tokens) < 4 or not tokens[0].isdigit():
            continue
        name = tokens[-1]
        if name == target_image:
            result["exists"] = True
            size_token = tokens[2] if tokens[2].isdigit() else next(
                (t for t in tokens[1:] if t.isdigit()), None
            )
            if size_token:
                result["size_mb"] = bytes_to_mb(size_token)
                result["detail"] = f"Image present ({result['size_mb']} MB)"
            else:
                result["detail"] = "Image present (size not parsed)"
            break
        if name.lower() == target_image.lower():
            case_mismatch = name

    if not result["exists"]:
        if case_mismatch:
            result["detail"] = (f"Image NOT found — but '{case_mismatch}' exists "
                                f"(file name case differs from TARGET_IMAGE)")
        else:
            result["detail"] = f"Image NOT found (free {result['free_mb']} MB)"

    safe_print(f"  [{hostname}] {flash_label} -> {result['detail']}")
    return result


# ───────────────────────── PER-DEVICE WORKFLOW ─────────────────────────
def base_result(host):
    return {
        "host": host, "hostname": "N/A", "device_type": "N/A", "model": "N/A",
        "version": "N/A", "ping": False, "rtt": "N/A", "tcp22": False,
        "ssh_auth": "NOT_TRIED", "is_stack": False, "flash_results": [],
        "overall_status": "UNREACHABLE", "summary": "",
    }


def check_device(host, username, password, target_image):
    r = base_result(host)
    try:
        safe_print(f"\n[START] {host} - ICMP check...")
        r["ping"], r["rtt"] = ping_host(host)

        r["tcp22"], banner = check_tcp_port(host)
        safe_print(f"[REACH] {host} - ping={'OK' if r['ping'] else 'FAIL'} "
                   f"rtt={r['rtt']}ms tcp/22={'OPEN' if r['tcp22'] else 'CLOSED'}")

        if not r["ping"] and not r["tcp22"]:
            r["overall_status"] = "UNREACHABLE"
            r["summary"] = "No ICMP response and TCP/22 closed"
            safe_print(f"[FAIL]  {host} - UNREACHABLE")
            return r

        if not r["tcp22"]:
            r["overall_status"] = "SSH_PORT_CLOSED"
            r["summary"] = "Pings but TCP/22 is closed or filtered"
            safe_print(f"[FAIL]  {host} - SSH_PORT_CLOSED")
            return r

        if not r["ping"] and SKIP_SSH_IF_NO_PING:
            r["overall_status"] = "ICMP_FILTERED"
            r["summary"] = "TCP/22 open but ICMP failed; SSH skipped by config"
            return r

        net_connect, device_type, auth_state = detect_device_type(host, username, password)
        r["ssh_auth"] = auth_state
        r["device_type"] = device_type or "N/A"

        if net_connect is None:
            r["overall_status"] = auth_state  # AUTH_FAILED / SSH_TIMEOUT / SSH_FAILED
            r["summary"] = f"TCP/22 open but SSH login did not succeed ({auth_state})"
            safe_print(f"[FAIL]  {host} - {auth_state}")
            return r

        r["hostname"] = net_connect.find_prompt().replace("#", "").strip()
        r["version"], r["model"] = get_running_version(net_connect)
        safe_print(f"[CONN]  {r['hostname']} ({host}) [{device_type}] "
                   f"model={r['model']} running={r['version']}")

        stack_members = get_stack_members(net_connect)
        r["is_stack"] = len(stack_members) > 1

        if r["is_stack"]:
            safe_print(f"[STACK] {r['hostname']} - members: {stack_members}")
            flash_labels = [f"flash-{m}:" for m in stack_members]
        else:
            flash_labels = ["flash:"]

        for flash_label in flash_labels:
            r["flash_results"].append(
                check_image_presence(net_connect, r["hostname"], flash_label, target_image)
            )

        net_connect.disconnect()

        all_exist = all(fr["exists"] for fr in r["flash_results"])
        any_exist = any(fr["exists"] for fr in r["flash_results"])

        if all_exist:
            r["overall_status"] = "IMAGE_PRESENT"
        elif any_exist:
            r["overall_status"] = "IMAGE_PARTIAL"
        else:
            r["overall_status"] = "IMAGE_MISSING"

        r["summary"] = " | ".join(f"{fr['flash']} {fr['detail']}" for fr in r["flash_results"])
        safe_print(f"[DONE]  {r['hostname']} ({host}) - {r['overall_status']}")
        return r

    except Exception as e:
        r["overall_status"] = "FAILED"
        r["summary"] = str(e)
        safe_print(f"[FAIL]  {host} - {e}")
        return r


# ───────────────────────── MAIN ─────────────────────────
STATUS_ORDER = [
    "IMAGE_PRESENT", "IMAGE_PARTIAL", "IMAGE_MISSING", "ICMP_FILTERED",
    "AUTH_FAILED", "SSH_TIMEOUT", "SSH_FAILED", "SSH_PORT_CLOSED",
    "UNREACHABLE", "FAILED",
]


def main():
    devices = load_devices(DEVICE_FILE)
    if not devices:
        print("No devices loaded. Exiting.")
        return

    print(f"Loaded {len(devices)} devices from '{DEVICE_FILE}'")
    print(f"Target image : {TARGET_IMAGE}")
    print(f"Threads      : {MAX_THREADS}")
    print("Mode         : reachability + image existence (no MD5)\n")

    start_time = datetime.now()
    timestamp = start_time.strftime("%Y%m%d_%H%M%S")
    reach_csv = os.path.join(REPORTS_DIR, f"reachability_report_{timestamp}.csv")
    image_csv = os.path.join(REPORTS_DIR, f"image_presence_report_{timestamp}.csv")
    log_file = os.path.join(LOGS_DIR, f"image_reachability_log_{timestamp}.txt")

    results = []
    total = len(devices)
    completed = 0
    status_counts = {s: 0 for s in STATUS_ORDER}

    def print_progress():
        present = status_counts["IMAGE_PRESENT"]
        missing = status_counts["IMAGE_MISSING"] + status_counts["IMAGE_PARTIAL"]
        unreach = (status_counts["UNREACHABLE"] + status_counts["SSH_PORT_CLOSED"]
                   + status_counts["SSH_TIMEOUT"] + status_counts["SSH_FAILED"]
                   + status_counts["AUTH_FAILED"] + status_counts["FAILED"])
        bar_filled = int((completed / total) * 30)
        bar = "#" * bar_filled + "-" * (30 - bar_filled)
        print(f"\n  PROGRESS [{bar}] {completed}/{total} | "
              f"Image:{present}  Missing/Partial:{missing}  Unreachable:{unreach}\n", flush=True)

    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        future_to_host = {
            executor.submit(check_device, host, USERNAME, PASSWORD, TARGET_IMAGE): host
            for host in devices
        }
        for future in as_completed(future_to_host):
            result = future.result()
            results.append(result)
            completed += 1
            status_counts[result["overall_status"]] = status_counts.get(result["overall_status"], 0) + 1
            print_progress()

    device_order = {host: idx for idx, host in enumerate(devices)}
    results.sort(key=lambda r: device_order.get(r["host"], 999999))

    run_stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ── Report 1: reachability, one row per device ──
    with open(reach_csv, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow([
            "#", "Host IP", "Hostname", "Model", "Running Version", "Device Type",
            "ICMP", "Avg RTT (ms)", "TCP/22", "SSH Auth", "Stack?",
            "Overall Status", "Summary", "Timestamp",
        ])
        for i, r in enumerate(results, 1):
            w.writerow([
                i, r["host"], r["hostname"], r["model"], r["version"], r["device_type"],
                "Up" if r["ping"] else "Down", r["rtt"],
                "Open" if r["tcp22"] else "Closed", r["ssh_auth"],
                "Yes" if r["is_stack"] else "No",
                r["overall_status"], r["summary"], run_stamp,
            ])
    print(f"\nReachability CSV : {reach_csv}")

    # ── Report 2: image presence, one row per flash ──
    with open(image_csv, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow([
            "#", "Host IP", "Hostname", "Stack?", "Flash", "Image",
            "Exists", "Size (MB)", "Free (MB)", "Detail", "Overall Status", "Timestamp",
        ])
        row = 1
        for r in results:
            if r["flash_results"]:
                for fr in r["flash_results"]:
                    w.writerow([
                        row, r["host"], r["hostname"], "Yes" if r["is_stack"] else "No",
                        fr["flash"], TARGET_IMAGE, "Yes" if fr["exists"] else "No",
                        fr["size_mb"], fr["free_mb"], fr["detail"],
                        r["overall_status"], run_stamp,
                    ])
                    row += 1
            else:
                w.writerow([
                    row, r["host"], r["hostname"], "N/A", "N/A", TARGET_IMAGE,
                    "Not checked", "N/A", "N/A", r["summary"],
                    r["overall_status"], run_stamp,
                ])
                row += 1
    print(f"Image CSV        : {image_csv}")

    # ── Detailed log ──
    with open(log_file, "w") as f:
        f.write("Image Reachability / Presence Report\n")
        f.write(f"Target image : {TARGET_IMAGE}\n")
        f.write(f"Run time     : {start_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Devices      : {len(results)}\n")
        f.write("=" * 78 + "\n\n")
        for idx, r in enumerate(results, 1):
            f.write(f"[{idx}] {r['host']} | {r['hostname']} | {r['model']} | "
                    f"running {r['version']}\n")
            f.write(f"     ICMP: {'Up' if r['ping'] else 'Down'} ({r['rtt']} ms) | "
                    f"TCP/22: {'Open' if r['tcp22'] else 'Closed'} | "
                    f"SSH: {r['ssh_auth']} | Stack: {r['is_stack']}\n")
            f.write(f"     Status: {r['overall_status']}\n")
            for fr in r["flash_results"]:
                f.write(f"     {fr['flash']} -> Exists: {fr['exists']} | "
                        f"Size: {fr['size_mb']} MB | Free: {fr['free_mb']} MB | {fr['detail']}\n")
            if not r["flash_results"]:
                f.write(f"     Detail: {r['summary']}\n")
            f.write("-" * 78 + "\n\n")
    print(f"Log              : {log_file}")

    # ── Console summary ──
    elapsed = datetime.now() - start_time
    print(f"\n{'=' * 55}")
    print(f"  Target image: {TARGET_IMAGE}")
    print(f"{'-' * 55}")
    for status in STATUS_ORDER:
        count = status_counts.get(status, 0)
        if count:
            print(f"  {status:<20} : {count}")
    print(f"{'=' * 55}")
    reachable = sum(1 for r in results if r["ssh_auth"] == "OK")
    print(f"  SSH-reachable        : {reachable}/{len(results)}")
    print(f"  Total time           : {elapsed}")

    if status_counts.get("IMAGE_MISSING") or status_counts.get("IMAGE_PARTIAL"):
        print("\n  Devices needing the image staged:")
        for r in results:
            if r["overall_status"] in ("IMAGE_MISSING", "IMAGE_PARTIAL"):
                free = ", ".join(str(fr["free_mb"]) for fr in r["flash_results"]) or "N/A"
                print(f"    - {r['host']:<16} {r['hostname']:<20} free: {free} MB")


if __name__ == "__main__":
    main()
