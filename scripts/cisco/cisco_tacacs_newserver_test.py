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
SCRIPT_DIR   = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, "..", ".."))
DATA_DIR     = os.path.join(PROJECT_ROOT, "data")
REPORTS_DIR  = os.path.join(PROJECT_ROOT, "reports", "cisco", "tacacs_newserver_test")
LOGS_DIR     = os.path.join(PROJECT_ROOT, "logs")
os.makedirs(REPORTS_DIR, exist_ok=True)
os.makedirs(LOGS_DIR, exist_ok=True)

# ============================ EDIT THESE ============================
DEVICE_FILE   = os.path.join(DATA_DIR, "devices.txt")
MAX_THREADS   = 10          # lower than the read-only audit: this touches config
CONNECT_TIMEOUT = 10

# Temporary group created for testing, then deleted. Must NOT collide with a
# real group name on any device.
TEST_GROUP_NAME = "LCL-NET-Access-ISE-TEST"

# New TACACS servers to validate before any production cutover.
NEW_SERVERS = ["10.191.160.9", "10.191.232.7"]

# Safety switch: when True, the script prints every command it WOULD send
# (with the key masked) and sends nothing. Flip to False to actually test.
DRY_RUN = True

# SSH credential fallback: the service account ([cisco_default] in
# credentials.ini) is tried first; if it is rejected (AUTH_FAIL), these LOCAL
# accounts are tried in order - one at a time - until one authenticates.
# Each entry is a section in credentials.ini, same convention used by
# cisco_detect_device_os.py and cisco_tacacs_validate.py:
#   [cisco_local]
#   username = ...
#   password = ...
#   enable_password = ...   (optional; falls back to that account's own password)
# A section missing a username or password is skipped automatically, so you
# don't need to fill in every slot. The report shows which account actually
# logged in.
FALLBACK_PROFILES = ["cisco_local", "cisco_local2", "cisco_local3", "cisco_local4", "cisco_local5"]

# The shared key for the NEW servers and the test credentials are read from
# credentials.ini (never hardcode them here). Add a [tacacs_migration] section:
#   [tacacs_migration]
#   key = Y!9H7B16Ju
#   test_username = SVC_NMS_TACACS
#   test_password = ....
# Test credentials fall back to the service account if not set.
# ====================================================================

print_lock = threading.Lock()

# Anything that looks like a shared key in a command we log gets masked.
_KEY_MASK_RE = re.compile(r"(\bkey\s+(?:\d+\s+)?)(\S+)", re.IGNORECASE)


def mask(cmd: str) -> str:
    """Hide the shared key when echoing a command to console/log."""
    return _KEY_MASK_RE.sub(r"\1****", cmd)


def safe_print(msg):
    with print_lock:
        print(msg)


def load_devices(filename):
    try:
        with open(filename, "r") as f:
            raw = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        seen, unique = set(), []
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


MODEL_PATTERNS = [
    re.compile(r"^Model\s+number\s*:\s*(\S+)", re.IGNORECASE | re.MULTILINE),
    re.compile(r"cisco\s+(Nexus[\w/-]*(?:\s+[\w/-]+)?)\s+Chassis", re.IGNORECASE),
    re.compile(r"cisco\s+(\S+)\s+\([^)]*\)\s+processor", re.IGNORECASE),
    re.compile(r"cisco\s+(\S+)\s+Chassis", re.IGNORECASE),
    re.compile(r"cisco\s+(WS-\S+|N\dK-\S+|ISR\S+|ASR\S+|C\d\S+|CISCO\S+)", re.IGNORECASE),
]


def parse_model(ver: str) -> str:
    """Best-effort device model/series from `show version` output."""
    for rx in MODEL_PATTERNS:
        m = rx.search(ver or "")
        if m:
            return m.group(1).strip()
    return "unknown"


def _try_connect(host, user, pwd, sec, device_type):
    return ConnectHandler(
        device_type=device_type, host=host, username=user, password=pwd,
        secret=sec or pwd, fast_cli=False, timeout=CONNECT_TIMEOUT,
        session_timeout=60,
    )


def connect_and_detect(host, creds):
    """Try each credential set in order (service account first, then local
    fallbacks). Enters enable mode if we land in user EXEC (send_config_set
    later requires privileged mode), then determines platform (NX-OS vs
    IOS-XE/IOS) and model from `show version`. NX-OS boxes are reconnected
    with the correct netmiko device_type.
    Returns (conn, platform, model, fail_reason, login_as).
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
            if any(s in err for s in ("timed out", "timeout", "refused", "unreachable")):
                return None, None, "", "TIMEOUT", ""   # network down: other creds won't help
            last_reason = "AUTH_FAIL" if any(
                s in err for s in ("authentication", "auth", "password")) else "SSH_ERROR"
            continue  # try the next credential

        try:
            if not conn.check_enable_mode():
                conn.enable()
        except Exception:
            pass

        try:
            ver = conn.send_command("show version", read_timeout=30)
        except Exception:
            ver = ""
        model = parse_model(ver)

        if re.search(r"NX-?OS|Nexus", ver, re.IGNORECASE):
            # Reconnect with the proper NX-OS driver.
            try:
                conn.disconnect()
            except Exception:
                pass
            try:
                conn = _try_connect(host, user, pwd, sec, "cisco_nxos")
                return conn, "nxos", model, "", label
            except Exception as e:
                return None, None, "", f"SSH_ERROR ({e})", label

        return conn, "ios", model, "", label

    return None, None, "", last_reason, ""


# ---- Parsing existing config so the test group can mirror reachability ----
GROUP_HEADER_RE = re.compile(r"^\s*aaa\s+group\s+server\s+tacacs\+\s+(\S+)", re.IGNORECASE)
SRC_IF_RE       = re.compile(r"^\s*(?:ip\s+tacacs\s+)?source-interface\s+(\S+)", re.IGNORECASE)
VRF_RE          = re.compile(r"^\s*(?:ip\s+vrf\s+forwarding|use-vrf)\s+(\S+)", re.IGNORECASE)


def find_existing_group_context(aaa_config: str):
    """Return (group_name, source_interface, vrf) from the first real
    `aaa group server tacacs+` block that has a source-interface -- used to make
    the temporary test group source traffic the same way (ACL/routing parity).
    Any of the three may be None."""
    current = None
    found_group = src = vrf = None
    for line in aaa_config.splitlines():
        m = GROUP_HEADER_RE.match(line)
        if m:
            current = m.group(1)
            if current.upper() == TEST_GROUP_NAME.upper():
                current = None  # ignore a leftover test group
            continue
        if current is None:
            continue
        if line and not line.startswith((" ", "\t")):
            current = None
            continue
        ms = SRC_IF_RE.match(line)
        if ms and found_group is None:
            found_group, src = current, ms.group(1)
        mv = VRF_RE.match(line)
        if mv and found_group == current:
            vrf = mv.group(1)
    return found_group, src, vrf


def _bad(out):
    """True if the command output is empty or an IOS parser error (so the
    `| section` filter wasn't supported on this image)."""
    low = (out or "").lower()
    return (not out) or any(m in low for m in (
        "% invalid input", "% incomplete command", "% ambiguous command"))


def fetch_aaa_tacacs(conn):
    """Return (aaa_cfg, tac_cfg) robustly across IOS releases. Old IOS (e.g.
    12.2) supports neither `| section` nor `show running-config aaa`; for those
    grab the full running-config once and parse the groups out of that."""
    aaa = conn.send_command("show running-config | section aaa", read_timeout=30)
    tac = conn.send_command("show running-config | section tacacs", read_timeout=30)
    if _bad(aaa) or _bad(tac):
        full = conn.send_command("show running-config", read_timeout=90)
        if not _bad(full):
            return full, full
    return aaa, tac


def build_test_group_cmds(platform, server_ip, key, src_if, vrf):
    """Config lines to create the temp test group for ONE server."""
    cmds = [f"aaa group server tacacs+ {TEST_GROUP_NAME}"]
    if platform == "nxos":
        # NX-OS has no server-private; the host+key is global, referenced by name.
        cmds.append(f"server {server_ip}")
        if vrf:
            cmds.append(f"use-vrf {vrf}")
        if src_if:
            cmds.append(f"source-interface {src_if}")
    else:
        cmds.append(f"server-private {server_ip} key {key}")
        if vrf:
            cmds.append(f"ip vrf forwarding {vrf}")
        if src_if:
            cmds.append(f"ip tacacs source-interface {src_if}")
    return cmds


def host_already_present(tacacs_raw, ip):
    return re.search(rf"^\s*tacacs-server\s+host\s+{re.escape(ip)}\b",
                     tacacs_raw or "", re.IGNORECASE | re.MULTILINE) is not None


def classify_test(out: str) -> str:
    """Classify `test aaa group` output:
      PASS         - server reachable AND credentials accepted
      AUTH_FAIL    - server reachable but auth rejected (bad creds OR wrong key)
      UNREACHABLE  - could not reach/contact the server (network/source issue)
      FAIL         - unrecognised output"""
    low = (out or "").lower()
    if "successfully authenticated" in low:
        return "PASS"
    if any(s in low for s in ("not responding", "no response", "could not connect",
                              "cannot communicate", "unreachable", "timed out",
                              "timeout", "no server")):
        return "UNREACHABLE"
    if any(s in low for s in ("not authenticated", "authentication failed",
                              "auth failed", "denied", "rejected", "incorrect",
                              "failed")):
        return "AUTH_FAIL"
    return "FAIL"


def _test_message(out: str) -> str:
    keep = [l.strip() for l in (out or "").splitlines()
            if l.strip() and not l.strip().startswith("test aaa")]
    return " | ".join(keep)[:250]


def run_auth_test(conn, platform, test_user, test_pass):
    """Run `test aaa group` and return (result, command, message). The password
    is masked in the returned command string for safe logging."""
    if platform == "nxos":
        cmd = f"test aaa group {TEST_GROUP_NAME} {test_user} {test_pass}"
    else:
        cmd = f"test aaa group {TEST_GROUP_NAME} {test_user} {test_pass} legacy"
    out = conn.send_command_timing(cmd, read_timeout=45)
    safe_cmd = cmd.replace(test_pass, "****") if test_pass else cmd
    return classify_test(out), safe_cmd, _test_message(out)


def check_device(host, creds, test_user, test_pass, new_key):
    device_start = datetime.now()

    def _result(hostname, platform, login_status, overall, detail,
                src_if, per_server, cleanup, test_msg="", login_as="-"):
        duration = round((datetime.now() - device_start).total_seconds(), 1)
        return {
            "host": host, "hostname": hostname, "platform": platform or "N/A",
            "model": model or "-",
            "login_status": login_status, "login_as": login_as or "-",
            "overall": overall, "detail": detail,
            "src_if": src_if or "-", "per_server": per_server,
            "cleanup": cleanup, "test_msg": test_msg,
            "duration_s": duration,
            "tested_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }

    safe_print(f"\n[START] Connecting to {host}...")
    conn, platform, model, fail_reason, login_as = connect_and_detect(host, creds)
    if conn is None:
        safe_print(f"[{fail_reason}]  {host} - Could not connect.")
        return _result("N/A", None, fail_reason, "N/A",
                       f"SSH failed: {fail_reason}", None, "", "N/A", login_as=login_as)

    hostname = "N/A"
    added_test_group = False
    added_hosts = []          # NX-OS global hosts we created and must remove
    per_server_results = []   # list of "ip:RESULT"
    test_msgs = []            # captured `test aaa` output per server

    try:
        hostname = conn.find_prompt().replace("#", "").strip()
        safe_print(f"[CONN]  {hostname} ({host}) [{platform}] - Login: OK as {login_as}")
        conn.send_command("terminal length 0", read_timeout=10)

        aaa_cfg, tac_cfg = fetch_aaa_tacacs(conn)

        # SAFETY: refuse to operate if a group with our test name already
        # exists -- otherwise the 'no aaa group ... TEST' cleanup would delete
        # real, possibly in-use config. Leave the device completely untouched.
        if re.search(rf"^\s*aaa\s+group\s+server\s+tacacs\+\s+{re.escape(TEST_GROUP_NAME)}\b",
                     aaa_cfg or "", re.IGNORECASE | re.MULTILINE):
            safe_print(f"  [{hostname}] SKIPPED -- group '{TEST_GROUP_NAME}' "
                       f"already exists; device left untouched.")
            return _result(hostname, platform, "OK", "SKIPPED",
                           f"Group {TEST_GROUP_NAME} already present; "
                           f"no changes made.", None, "", "N/A", login_as=login_as)

        _group, src_if, vrf = find_existing_group_context(aaa_cfg or "")

        for ip in NEW_SERVERS:
            create_cmds = build_test_group_cmds(platform, ip, new_key, src_if, vrf)
            nxos_host_cmd = (f"tacacs-server host {ip} key {new_key}"
                             if platform == "nxos" else None)

            if DRY_RUN:
                safe_print(f"  [DRY-RUN {hostname}] would test {ip}:")
                if nxos_host_cmd and not host_already_present(tac_cfg, ip):
                    safe_print(f"      {mask(nxos_host_cmd)}")
                for c in create_cmds:
                    safe_print(f"      {mask(c)}")
                test_cmd = (f"test aaa group {TEST_GROUP_NAME} {test_user} **** "
                            + ("" if platform == "nxos" else "legacy"))
                safe_print(f"      {test_cmd.strip()}")
                safe_print(f"      no aaa group server tacacs+ {TEST_GROUP_NAME}")
                per_server_results.append(f"{ip}:DRY-RUN")
                continue

            # --- live test for this server ---
            # NX-OS: add the global host (only if not already configured).
            if nxos_host_cmd and not host_already_present(tac_cfg, ip):
                conn.send_config_set([nxos_host_cmd], read_timeout=30)
                added_hosts.append(ip)

            conn.send_config_set(create_cmds, read_timeout=30)
            added_test_group = True

            res, _cmd, msg = run_auth_test(conn, platform, test_user, test_pass)
            per_server_results.append(f"{ip}:{res}")
            if msg:
                test_msgs.append(f"[{ip}] {msg}")
            safe_print(f"  [{hostname}] {ip} -> {res}")

            # tear down this server's test group before the next iteration
            conn.send_config_set(
                [f"no aaa group server tacacs+ {TEST_GROUP_NAME}"], read_timeout=30)
            added_test_group = False

        if DRY_RUN:
            return _result(hostname, platform, "OK", "DRY-RUN",
                           "Dry-run only; no commands sent.",
                           src_if, "; ".join(per_server_results), "N/A", login_as=login_as)

        passes = [r for r in per_server_results if r.endswith("PASS")]
        if len(passes) == len(NEW_SERVERS):
            overall = "PASS"
        elif passes:
            overall = "PARTIAL"
        elif all(r.endswith("UNREACHABLE") for r in per_server_results):
            overall = "UNREACHABLE"        # server not contactable from this device
        elif any(r.endswith("AUTH_FAIL") for r in per_server_results):
            overall = "AUTH_FAIL"          # reachable but key/credentials rejected
        else:
            overall = "FAIL"
        detail = (f"{len(passes)}/{len(NEW_SERVERS)} new servers authenticated "
                  f"(src-if {src_if or 'default'})")
        return _result(hostname, platform, "OK", overall, detail,
                       src_if, "; ".join(per_server_results), "OK",
                       " ;; ".join(test_msgs), login_as=login_as)

    except Exception as e:
        safe_print(f"[FAIL]  {host} - {e}")
        return _result(hostname, platform, "OK", "ERROR", str(e),
                       None, "; ".join(per_server_results), "SEE_BELOW",
                       " ;; ".join(test_msgs), login_as=login_as)

    finally:
        # GUARANTEED cleanup: remove the test group and any host we added.
        # Never `write memory` -- nothing here should persist.
        if not DRY_RUN:
            cleanup_cmds = [f"no aaa group server tacacs+ {TEST_GROUP_NAME}"] \
                           if added_test_group else []
            cleanup_cmds += [f"no tacacs-server host {ip} key {new_key}"
                             for ip in added_hosts]
            if cleanup_cmds:
                try:
                    conn.send_config_set(cleanup_cmds, read_timeout=30)
                    safe_print(f"  [{hostname}] cleanup done (test config removed, not saved)")
                except Exception as ce:
                    safe_print(f"  [{hostname}] !! CLEANUP FAILED: {ce} "
                               f"-- manually remove {TEST_GROUP_NAME} on {host}")
        try:
            conn.disconnect()
        except Exception:
            pass


def _prompt_if_empty(label, stored, secret=False):
    if stored:
        return stored
    while True:
        val = (getpass.getpass if secret else input)(f"{label}: ").strip()
        if val:
            return val
        print(f"  [!] {label} cannot be empty.")


def main():
    print("=" * 55)
    print("  TACACS NEW-SERVER TEST  (creates temp test group, no prod change)")
    if DRY_RUN:
        print("  *** DRY-RUN MODE: no commands will be sent ***")
    print("=" * 55)

    username = _prompt_if_empty("SSH Username", config.get_cred('cisco_default', 'username'))
    password = _prompt_if_empty("SSH Password", config.get_cred('cisco_default', 'password'), secret=True)
    secret    = config.get_cred('cisco_default', 'enable_password')

    # Test identity + new-server key (fall back to the service account).
    test_user = config.get_cred('tacacs_migration', 'test_username') or username
    test_pass = config.get_cred('tacacs_migration', 'test_password') or password
    new_key   = config.get_cred('tacacs_migration', 'key')
    if not DRY_RUN and not new_key:
        new_key = _prompt_if_empty("New TACACS shared key", "", secret=True)

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

    print(f"\nLoaded {len(devices)} devices from '{DEVICE_FILE}'")
    print(f"Test group       : {TEST_GROUP_NAME}")
    print(f"New servers      : {', '.join(NEW_SERVERS)}")
    print(f"Test username    : {test_user}")
    print(f"Login creds      : {' -> '.join(c[3] for c in creds)}")
    print(f"Threads          : {MAX_THREADS}\n")

    start_time = datetime.now()
    timestamp = start_time.strftime("%Y%m%d_%H%M%S")
    csv_file = os.path.join(REPORTS_DIR, f"tacacs_newserver_test_{timestamp}.csv")
    log_file = os.path.join(LOGS_DIR,    f"tacacs_newserver_test_{timestamp}.txt")

    results, completed = [], 0
    total = len(devices)
    login_counts, overall_counts = {}, {}

    try:
        with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            futures = {
                executor.submit(check_device, host, creds,
                                test_user, test_pass, new_key): host
                for host in devices
            }
            for future in as_completed(futures):
                r = future.result()
                results.append(r)
                completed += 1
                login_counts[r["login_status"]] = login_counts.get(r["login_status"], 0) + 1
                overall_counts[r["overall"]] = overall_counts.get(r["overall"], 0) + 1
                safe_print(f"  PROGRESS {completed}/{total}")
    except KeyboardInterrupt:
        print(f"\n[!] Interrupted. Saving {len(results)} result(s)...")

    order = {h: i for i, h in enumerate(devices)}
    results.sort(key=lambda r: order.get(r["host"], 999999))

    with open(csv_file, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["#", "Host IP", "Hostname", "Platform", "Model", "Login Status",
                    "Login As", "Overall", "Per-Server Result", "Source-If", "Cleanup",
                    "Test Output", "Detail", "Duration (s)", "Tested At"])
        for idx, r in enumerate(results, 1):
            w.writerow([idx, r["host"], r["hostname"], r["platform"], r["model"],
                        r["login_status"], r["login_as"], r["overall"], r["per_server"],
                        r["src_if"], r["cleanup"], r["test_msg"], r["detail"],
                        r["duration_s"], r["tested_at"]])
    print(f"\nCSV saved to: {csv_file}")

    with open(log_file, "w") as f:
        f.write("TACACS New-Server Test Report\n")
        f.write(f"Test group : {TEST_GROUP_NAME}\n")
        f.write(f"New servers: {', '.join(NEW_SERVERS)}\n")
        f.write(f"Dry-run    : {DRY_RUN}\n")
        f.write(f"Run time   : {start_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 70 + "\n\n")
        for idx, r in enumerate(results, 1):
            f.write(f"[{idx}] {r['host']} | {r['hostname']} | {r['platform']} "
                    f"({r['model']}) | Login: {r['login_status']} as {r['login_as']} | "
                    f"Overall: {r['overall']} | Cleanup: {r['cleanup']} | "
                    f"{r['duration_s']}s\n")
            f.write(f"     Per-Server : {r['per_server']}\n")
            f.write(f"     Source-If  : {r['src_if']}\n")
            if r["test_msg"]:
                f.write(f"     Test Output: {r['test_msg']}\n")
            f.write(f"     Detail     : {r['detail']}\n")
            f.write("-" * 70 + "\n\n")
    print(f"Log saved to: {log_file}")

    elapsed = datetime.now() - start_time
    print(f"\n{'='*55}")
    print(f"  --- Device Login ---")
    for k in ("OK", "TIMEOUT", "AUTH_FAIL", "SSH_ERROR"):
        print(f"  {k:20}: {login_counts.get(k, 0)}")
    print(f"  --- Test Result ---")
    for k in ("PASS", "PARTIAL", "AUTH_FAIL", "UNREACHABLE", "FAIL",
              "SKIPPED", "DRY-RUN", "ERROR", "N/A"):
        if overall_counts.get(k):
            print(f"  {k:20}: {overall_counts.get(k, 0)}")
    print(f"{'='*55}")
    print(f"Total devices : {len(results)} | Total time : {elapsed}")
    if any(r["cleanup"] not in ("OK", "N/A") for r in results):
        print("\n[!] One or more devices reported a cleanup problem -- check the log "
              f"and manually verify '{TEST_GROUP_NAME}' is gone.")


if __name__ == "__main__":
    main()
