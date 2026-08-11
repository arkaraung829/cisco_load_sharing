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
    for pkg in packages:
        try:
            importlib.import_module(pkg)
        except ImportError:
            print(f"[SETUP] '{pkg}' not found. Installing...")
            r = subprocess.run([sys.executable, "-m", "pip", "install", pkg],
                               capture_output=True, text=True)
            if r.returncode != 0:
                print(f"[SETUP] ERROR installing '{pkg}':\n{r.stderr}")
                sys.exit(1)
            print(f"[SETUP] '{pkg}' installed.")

install_if_missing(REQUIRED_PACKAGES)

# ===== IMPORTS =====
from netmiko import ConnectHandler
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import csv
import threading
import re
import getpass

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import config

# ===== PATHS =====
SCRIPT_DIR   = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, "..", ".."))
DATA_DIR     = os.path.join(PROJECT_ROOT, "data")
REPORTS_DIR  = os.path.join(PROJECT_ROOT, "reports", "cisco", "tacacs_validate")
LOGS_DIR     = os.path.join(PROJECT_ROOT, "logs")
os.makedirs(REPORTS_DIR, exist_ok=True)
os.makedirs(LOGS_DIR, exist_ok=True)

# ============================ EDIT THESE ============================
# Input: one device IP per line in a plain text file named after this script,
# in the SAME directory as the script (cisco_tacacs_validate.txt). Lines that
# are blank or start with '#' are ignored. Results are written to a standalone
# CSV under reports/cisco/tacacs_validate/.
DEVICE_FILE = os.path.join(SCRIPT_DIR,
                           os.path.splitext(os.path.basename(__file__))[0] + ".txt")
MAX_THREADS     = 15
CONNECT_TIMEOUT = 10

# The NEW TACACS servers Prime is migrating to. Validation confirms THESE
# authenticate (and, where possible, that the device is actually using them).
NEW_SERVERS = ["10.191.160.9", "10.191.232.7"]

# Force the test to run against a SPECIFIC group on every device, instead of
# auto-detecting the active login group. Set this to your temp test group
# (e.g. "OCI-ISE-TEST") to validate it fleet-wide right after Prime pushes it;
# leave "" to auto-detect the active login group (post-cutover validation).
GROUP_OVERRIDE = "OCI-ISE-TEST"

# SSH credential fallback: the service account ([cisco_default] in
# credentials.ini) is tried first; if it is rejected (AUTH_FAIL), these LOCAL
# accounts are tried in order - one at a time - until one authenticates.
# Each entry is a section in credentials.ini, same convention used by
# cisco_detect_device_os.py:
#   [cisco_local]
#   username = ...
#   password = ...
#   enable_password = ...   (optional; falls back to the service account's secret)
# A section missing a username or password is skipped automatically, so you
# don't need to fill in every slot. The report shows which account actually
# logged in.
FALLBACK_PROFILES = ["cisco_local", "cisco_local2", "cisco_local3", "cisco_local4", "cisco_local5"]
# ====================================================================
#
# 100% READ-ONLY. Sends NO configuration and saves nothing. It only runs
# `show` commands and `test aaa` (a test authentication, which does not change
# device config -- it does create an auth event on ISE, which is expected).
# Use AFTER you push the server swap via Cisco Prime, to confirm the new
# servers work. `test aaa` is read-only but reaches ISE.
# ====================================================================

print_lock = threading.Lock()


def safe_print(msg):
    with print_lock:
        print(msg)


def load_devices(filename):
    try:
        with open(filename) as f:
            raw = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        seen, uniq = set(), []
        for h in raw:
            if h not in seen:
                seen.add(h); uniq.append(h)
        return uniq
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


def parse_model(ver):
    for rx in MODEL_PATTERNS:
        m = rx.search(ver or "")
        if m:
            return m.group(1).strip()
    return "unknown"


def _try_connect(host, user, pwd, sec, device_type):
    return ConnectHandler(device_type=device_type, host=host, username=user,
                          password=pwd, secret=sec or pwd, fast_cli=False,
                          timeout=CONNECT_TIMEOUT, session_timeout=90)


def connect_and_detect(host, creds):
    """Try each credential set in order (service account first, then local
    fallbacks like ciscologin/enterprise). Enters enable mode if we land in
    user EXEC, then detects platform + model.
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
                s in err for s in ("authentication", "auth", "password", "denied")) else "SSH_ERROR"
            continue                                    # try the next credential

        try:
            if not conn.check_enable_mode():
                conn.enable()
        except Exception:
            pass
        try:
            ver = conn.send_command("show version", read_timeout=30)
        except Exception:
            ver = ""
        platform = "nxos" if re.search(r"NX-?OS|Nexus", ver, re.IGNORECASE) else "ios"
        model = parse_model(ver)

        if platform == "nxos":
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


# ---- config parsing: resolve each tacacs+ group's member server IPs ----
GROUP_HEADER_RE = re.compile(r"^\s*aaa\s+group\s+server\s+tacacs\+\s+(\S+)", re.IGNORECASE)
SP_RE        = re.compile(r"^\s*server-private\s+(\d+\.\d+\.\d+\.\d+)", re.IGNORECASE)
SRV_NAME_RE  = re.compile(r"^\s*server\s+name\s+(\S+)", re.IGNORECASE)
SRV_IP_RE    = re.compile(r"^\s*server\s+(\d+\.\d+\.\d+\.\d+)", re.IGNORECASE)
TS_HOST_RE   = re.compile(r"^\s*tacacs-server\s+host\s+(\d+\.\d+\.\d+\.\d+)", re.IGNORECASE)
TS_NAME_HDR  = re.compile(r"^\s*tacacs\s+server\s+(\S+)", re.IGNORECASE)
ADDR_IPV4_RE = re.compile(r"^\s*address\s+ipv4\s+(\d+\.\d+\.\d+\.\d+)", re.IGNORECASE)


def name_to_ip_map(cfg):
    """Map `tacacs server <name>` -> address ipv4 <ip> (modern IOS-XE)."""
    m, cur = {}, None
    for line in cfg.splitlines():
        h = TS_NAME_HDR.match(line)
        if h:
            cur = h.group(1); continue
        if cur:
            a = ADDR_IPV4_RE.match(line)
            if a:
                m[cur] = a.group(1); cur = None
            elif line and not line.startswith((" ", "\t")):
                cur = None
    return m


def parse_groups(cfg):
    """Return {group_name: [server_ip, ...]} resolving server-private / server
    <ip> / server name <name> across IOS, IOS-XE and NX-OS."""
    nmap = name_to_ip_map(cfg)
    groups, cur = {}, None
    for line in cfg.splitlines():
        g = GROUP_HEADER_RE.match(line)
        if g:
            cur = g.group(1); groups.setdefault(cur, [])
            continue
        if cur is None:
            continue
        if line and not line.startswith((" ", "\t")):
            cur = None; continue
        for rx, conv in ((SP_RE, None), (SRV_NAME_RE, nmap), (SRV_IP_RE, None)):
            mm = rx.match(line)
            if mm:
                val = mm.group(1)
                ip = conv.get(val) if conv else val
                if ip and ip not in groups[cur]:
                    groups[cur].append(ip)
                break
    return groups


def parse_global_servers(cfg):
    """Servers defined at GLOBAL level -- members of the implicit `group tacacs+`
    (and referenceable by `server name`). These live OUTSIDE any `aaa group
    server tacacs+` block, so parse_groups() never sees them:
        tacacs server <name> / address ipv4 <ip>     (modern IOS-XE named)
        tacacs-server host <ip>                       (legacy IOS / NX-OS)
    Returns de-duped list like ['KDC_TACACS=10.62.193.9', '10.0.0.1']."""
    out, seen, cur = [], set(), None
    for line in cfg.splitlines():
        mh = TS_HOST_RE.match(line)
        if mh:
            cur = None
            ip = mh.group(1)
            if ip not in seen:
                seen.add(ip); out.append(ip)
            continue
        h = TS_NAME_HDR.match(line)
        if h:
            cur = h.group(1); continue
        if cur:
            a = ADDR_IPV4_RE.match(line)
            if a:
                ip = a.group(1)
                if ip not in seen:
                    seen.add(ip); out.append(f"{cur}={ip}")
                cur = None
            elif line and not line.startswith((" ", "\t")):
                cur = None
    return out


def _bad(out):
    low = (out or "").lower()
    return (not out) or any(m in low for m in (
        "% invalid input", "% incomplete command", "% ambiguous command"))


def fetch_config(conn):
    cfg = conn.send_command("show running-config | section aaa", read_timeout=30)
    tac = conn.send_command("show running-config | section tacacs", read_timeout=30)
    if _bad(cfg) or _bad(tac):
        full = conn.send_command("show running-config", read_timeout=90)
        if not _bad(full):
            return full
    # line config (vty/con) is needed to find which login method list is active
    ln = conn.send_command("show running-config | section ^line", read_timeout=30)
    if _bad(ln):
        ln = ""
    return (cfg or "") + "\n" + (tac or "") + "\n" + ln


LOGIN_LIST_RE = re.compile(r"^\s*aaa\s+authentication\s+login\s+(\S+)\s+(.+)", re.IGNORECASE)
LINE_HDR_RE   = re.compile(r"^\s*line\s+(con|vty|aux)", re.IGNORECASE)
LOGIN_AUTH_RE = re.compile(r"^\s*login\s+authentication\s+(\S+)", re.IGNORECASE)
GROUP_TOKEN_RE = re.compile(r"group\s+(\S+)", re.IGNORECASE)


def parse_login_lists(cfg):
    """Map each `aaa authentication login <list> ...` to its ordered groups
    (first = primary). `group tacacs+` is the implicit/global group."""
    lists = {}
    for line in cfg.splitlines():
        m = LOGIN_LIST_RE.match(line)
        if m:
            lists[m.group(1)] = GROUP_TOKEN_RE.findall(m.group(2))
    return lists


def find_active_login(cfg):
    """Which login method list is bound to the lines operators use. Returns
    (list_name, scope). Prefers vty (remote/SSH), then console, then 'default'."""
    cur, vty, con = None, None, None
    for line in cfg.splitlines():
        h = LINE_HDR_RE.match(line)
        if h:
            cur = h.group(1).lower(); continue
        if cur:
            la = LOGIN_AUTH_RE.match(line)
            if la:
                if cur == "vty" and vty is None:
                    vty = la.group(1)
                elif cur == "con" and con is None:
                    con = la.group(1)
            elif line and not line.startswith((" ", "\t")):
                cur = None
    if vty:
        return vty, "vty"
    if con:
        return con, "con"
    return "default", "default"


def pick_group(groups):
    """Choose the tacacs+ group to validate: prefer one that already contains a
    NEW server (post-Prime); else the group with the most servers."""
    real = {g: ips for g, ips in groups.items() if not g.upper().endswith("-TEST")}
    if not real:
        return None, []
    for g, ips in real.items():
        if any(ip in ips for ip in NEW_SERVERS):
            return g, ips
    g = max(real, key=lambda k: len(real[k]))
    return g, real[g]


def classify_test(out):
    low = (out or "").lower()
    if "successfully authenticated" in low:
        return "PASS"
    if any(s in low for s in ("not responding", "no response", "could not connect",
                              "cannot communicate", "unreachable", "timed out",
                              "timeout", "no server")):
        return "UNREACHABLE"
    if any(s in low for s in ("not authenticated", "authentication failed",
                              "denied", "rejected", "incorrect", "failed")):
        return "AUTH_FAIL"
    return "FAIL"


def _msg(out):
    keep = [l.strip() for l in (out or "").splitlines()
            if l.strip() and not l.strip().lower().startswith("test aaa")]
    return " | ".join(keep)[:250]


def test_one(conn, platform, group, test_user, test_pass):
    """Read-only `test aaa group <group>` against ONE group (works on IOS and
    NX-OS). Returns (result, message)."""
    cmd = f"test aaa group {group} {test_user} {test_pass}"
    if platform != "nxos":
        cmd += " legacy"
    out = conn.send_command_timing(cmd, read_timeout=45)
    return classify_test(out), _msg(out)


def check_device(host, creds, test_user, test_pass):
    start = datetime.now()

    def R(hostname, platform, model, login, overall, group, servers,
          new_present, old_present, test_res, detail, test_msg="",
          global_srv="-", new_in_global="-", active_list="-", login_scope="-",
          login_as="-", existing_group="-", existing_servers="-", existing_result="-",
          migration="-", mig_reason="-"):
        return {
            "host": host, "hostname": hostname, "platform": platform or "N/A",
            "model": model or "-", "login": login, "login_as": login_as,
            "overall": overall, "migration": migration, "mig_reason": mig_reason,
            "active_list": active_list, "login_scope": login_scope,
            "group": group or "-", "servers": servers, "new_present": new_present,
            "old_present": old_present, "test_res": test_res, "detail": detail,
            "test_msg": test_msg, "global_srv": global_srv,
            "new_in_global": new_in_global,
            "existing_group": existing_group, "existing_servers": existing_servers,
            "existing_result": existing_result,
            "duration_s": round((datetime.now() - start).total_seconds(), 1),
            "tested_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }

    safe_print(f"\n[START] {host} ...")
    conn, platform, model, fail, login_as = connect_and_detect(host, creds)
    if conn is None:
        safe_print(f"[{fail}] {host}")
        return R("N/A", None, "", fail, "N/A", None, "", "", "", "",
                 f"SSH failed: {fail}")

    hostname = "N/A"
    try:
        hostname = conn.find_prompt().replace("#", "").replace(">", "").strip()
        safe_print(f"[CONN] {hostname} ({host}) [{platform}/{model}] as {login_as}")
        conn.send_command("terminal length 0", read_timeout=10)

        cfg = fetch_config(conn)
        groups = parse_groups(cfg)

        # Global / implicit `group tacacs+` servers (outside any named group).
        gsrv = parse_global_servers(cfg)
        gsrv_str = "; ".join(gsrv) if gsrv else "none"
        gsrv_ips = [e.split("=")[-1] for e in gsrv]
        new_in_global = "YES" if any(ip in gsrv_ips for ip in NEW_SERVERS) else "NO"

        # Active login path: which method list is bound to vty/console, and its
        # primary group -- that's the server set that authenticates real logins.
        login_lists = parse_login_lists(cfg)
        active_list, login_scope = find_active_login(cfg)
        ag = (login_lists.get(active_list) or [None])[0]

        # Resolve the EXISTING / active login group (the real production path).
        if ag and ag in groups:
            existing_group, existing_servers = ag, groups[ag]
        elif ag and ag.lower() == "tacacs+":
            existing_group, existing_servers = "tacacs+", gsrv_ips
        else:
            existing_group, existing_servers = pick_group(groups)

        # The PRIMARY group that drives the verdict: the override (test) group if
        # set, otherwise the existing group.
        if GROUP_OVERRIDE:
            group, servers = GROUP_OVERRIDE, groups.get(GROUP_OVERRIDE, [])
        else:
            group, servers = existing_group, existing_servers

        srv_str = ",".join(servers) if servers else "none"
        new_present = "YES" if any(ip in servers for ip in NEW_SERVERS) else "NO"
        old_present = "YES" if any(ip not in NEW_SERVERS for ip in servers) else "NO"

        if group is None and not existing_group:
            return R(hostname, platform, model, "OK", "NO_GROUP", None, srv_str,
                     new_present, old_present, "",
                     f"No testable tacacs+ group (active login list '{active_list}').",
                     global_srv=gsrv_str, new_in_global=new_in_global,
                     active_list=active_list, login_scope=login_scope, login_as=login_as)

        # Test the PRIMARY group.
        msgs = []
        if group:
            prim_res, prim_msg = test_one(conn, platform, group, test_user, test_pass)
            if prim_msg:
                msgs.append(f"[{group}] {prim_msg}")
        else:
            prim_res = "NO_GROUP"

        # ALSO test the EXISTING/active group (if different from the primary).
        if existing_group and existing_group != group:
            e_res, e_msg = test_one(conn, platform, existing_group, test_user, test_pass)
            existing_servers_str = ",".join(existing_servers) if existing_servers else "none"
            existing_result = f"{existing_group}:{e_res}"
            if e_msg:
                msgs.append(f"[{existing_group}] {e_msg}")
        else:
            existing_servers_str = srv_str
            existing_result = f"{existing_group or '-'}:{prim_res}"

        tmsg = " ;; ".join(msgs)
        per = [f"group {group}:{prim_res}"]
        safe_print(f"  [{hostname}] test={group}:{prim_res}  existing={existing_result}")

        passes = [p for p in per if p.endswith("PASS")]
        # Overall verdict
        if new_present == "NO":
            overall = "NEW_NOT_IN_GROUP"      # Prime change not applied/detected
        elif len(passes) == len(per):
            if platform == "ios" and old_present == "YES":
                overall = "PASS_AMBIGUOUS"     # group still has old servers too
            else:
                overall = "VALIDATED"
        elif passes:
            overall = "PARTIAL"
        elif any(p.endswith("UNREACHABLE") for p in per):
            overall = "UNREACHABLE"
        elif any(p.endswith("AUTH_FAIL") for p in per):
            overall = "AUTH_FAIL"
        else:
            overall = "FAIL"

        detail = {
            "VALIDATED": "New server(s) present and authenticated.",
            "PASS_AMBIGUOUS": ("Group test passed but old servers still in group "
                               "(IOS can't attribute to new) -- remove old then "
                               "re-test, or confirm via ISE live logs."),
            "NEW_NOT_IN_GROUP": "New server IPs not in the group yet (Prime change "
                                "not applied/detected).",
        }.get(overall, f"{len(passes)}/{len(per)} test(s) passed.")

        # MIGRATION status: complete only when the ACTIVE/production login group
        # both CONTAINS the new ISE servers AND authenticates successfully.
        existing_new = any(ip in existing_servers for ip in NEW_SERVERS)
        existing_pass = existing_result.rsplit(":", 1)[-1].strip() == "PASS"
        if existing_new and existing_pass:
            migration, mig_reason = "COMPLETE", "New ISE servers in active group AND authenticated."
        elif not existing_new:
            migration, mig_reason = "NOT_COMPLETE", "New servers not in active login group."
        elif not existing_pass:
            migration, mig_reason = "NOT_COMPLETE", f"Active group auth = {existing_result.rsplit(':',1)[-1].strip()}."
        else:
            migration, mig_reason = "NOT_COMPLETE", "Criteria not met."

        return R(hostname, platform, model, "OK", overall, group, srv_str,
                 new_present, old_present, "; ".join(per), detail, tmsg,
                 global_srv=gsrv_str, new_in_global=new_in_global,
                 active_list=active_list, login_scope=login_scope, login_as=login_as,
                 existing_group=existing_group or "-",
                 existing_servers=existing_servers_str, existing_result=existing_result,
                 migration=migration, mig_reason=mig_reason)

    except Exception as e:
        safe_print(f"[FAIL] {host} - {e}")
        return R(hostname, platform, model, "OK", "ERROR", None, "", "", "", "",
                 str(e))
    finally:
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


# Result columns written to the standalone output CSV (after #, Host IP, Hostname).
RESULT_COLS = ["TACACS Platform", "TACACS Model", "TACACS Login", "TACACS Login As",
               "TACACS Migration", "TACACS Migration Reason",
               "TACACS Overall", "TACACS Active Login List", "TACACS Login Scope",
               "TACACS Group (tested)", "TACACS Servers In Group", "TACACS New Present",
               "TACACS Old Present",
               "TACACS Existing Group", "TACACS Existing Servers", "TACACS Existing Result",
               "TACACS Global Servers (group tacacs+)", "TACACS New In Global",
               "TACACS Test Result", "TACACS Detail", "TACACS Test Output",
               "TACACS Validate Duration(s)", "TACACS Validated At"]


def _result_cols(r):
    return [r["platform"], r["model"], r["login"], r["login_as"],
            r["migration"], r["mig_reason"], r["overall"],
            r["active_list"], r["login_scope"], r["group"], r["servers"],
            r["new_present"], r["old_present"],
            r["existing_group"], r["existing_servers"], r["existing_result"],
            r["global_srv"], r["new_in_global"],
            r["test_res"], r["detail"], r["test_msg"], r["duration_s"], r["tested_at"]]


def main():
    print("=" * 60)
    print("  TACACS VALIDATE  (READ-ONLY: confirms NEW servers authenticate)")
    print("=" * 60)
    username = _prompt_if_empty("SSH Username", config.get_cred('cisco_default', 'username'))
    password = _prompt_if_empty("SSH Password", config.get_cred('cisco_default', 'password'), secret=True)
    secret    = config.get_cred('cisco_default', 'enable_password')
    test_user = config.get_cred('tacacs_migration', 'test_username') or username
    test_pass = config.get_cred('tacacs_migration', 'test_password') or password

    # SSH credential chain: service account first, then local fallbacks.
    creds = [(username, password, secret, "cisco_svc")]
    for prof in FALLBACK_PROFILES:
        p_pass = config.get_cred(prof, 'password')
        if not p_pass:
            continue
        p_user = config.get_cred(prof, 'username') or prof
        p_secret = config.get_cred(prof, 'enable_password') or p_pass
        creds.append((p_user, p_pass, p_secret, prof))

    # ---- read the device list (one IP per line, next to this script) ----
    ips = load_devices(DEVICE_FILE)
    if not ips:
        print(f"No devices loaded from: {DEVICE_FILE}")
        print("Create that file (one IP per line; '#' for comments).")
        return

    print(f"\nDevice list   : {os.path.basename(DEVICE_FILE)}")
    print(f"Devices       : {len(ips)}")
    print(f"New servers   : {', '.join(NEW_SERVERS)}")
    print(f"Test target   : {'group ' + GROUP_OVERRIDE + ' (forced)' if GROUP_OVERRIDE else 'active login group (auto-detect)'}")
    print(f"Test username : {test_user}")
    print(f"Login creds   : {' -> '.join(c[3] for c in creds)}")
    print(f"Threads       : {MAX_THREADS}\n")

    start = datetime.now()
    ts = start.strftime("%Y%m%d_%H%M%S")
    out_csv  = os.path.join(REPORTS_DIR, f"tacacs_validate_{ts}.csv")
    log_file = os.path.join(LOGS_DIR, f"tacacs_validate_{ts}.txt")

    results_by_ip, done, total = {}, 0, len(ips)
    overall_counts = {}

    try:
        with ThreadPoolExecutor(max_workers=MAX_THREADS) as ex:
            futs = {ex.submit(check_device, ip, creds, test_user, test_pass): ip
                    for ip in ips}
            for fu in as_completed(futs):
                r = fu.result()
                results_by_ip[r["host"]] = r
                done += 1
                overall_counts[r["overall"]] = overall_counts.get(r["overall"], 0) + 1
                safe_print(f"  PROGRESS {done}/{total}")
    except KeyboardInterrupt:
        print(f"\n[!] Interrupted. Saving {len(results_by_ip)} result(s)...")

    # ---- write a standalone results CSV (input device order) ----
    order = {ip: i for i, ip in enumerate(ips)}
    results = sorted(results_by_ip.values(),
                     key=lambda r: order.get(r["host"], 1_000_000))
    with open(out_csv, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["#", "Host IP", "Hostname"] + RESULT_COLS)
        for i, r in enumerate(results, 1):
            w.writerow([i, r["host"], r["hostname"]] + _result_cols(r))
    print(f"\nCSV saved to: {out_csv}")

    with open(log_file, "w") as f:
        f.write("TACACS Validation Report (read-only)\n")
        f.write(f"Device list: {DEVICE_FILE}\n")
        f.write(f"New servers: {', '.join(NEW_SERVERS)}\n")
        f.write(f"Run time   : {start.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 72 + "\n\n")
        for i, ip in enumerate(ips, 1):
            r = results_by_ip.get(ip)
            if not r:
                continue
            f.write(f"[{i}] {r['host']} | {r['hostname']} | {r['platform']} "
                    f"({r['model']}) | login as {r['login_as']} | {r['overall']} | "
                    f"MIGRATION: {r['migration']} | {r['duration_s']}s\n")
            f.write(f"    Migration   : {r['migration']} -- {r['mig_reason']}\n")
            f.write(f"    Active login: list '{r['active_list']}' on {r['login_scope']} "
                    f"-> group '{r['group']}'\n")
            f.write(f"    Servers     : {r['servers']}  (new_present={r['new_present']}, "
                    f"old_present={r['old_present']})\n")
            f.write(f"    Existing grp: {r['existing_group']} [{r['existing_servers']}] "
                    f"-> {r['existing_result']}\n")
            f.write(f"    Global srv  : {r['global_srv']}  (new_in_global={r['new_in_global']})\n")
            f.write(f"    Test Result : {r['test_res']}\n")
            if r["test_msg"]:
                f.write(f"    Test Output : {r['test_msg']}\n")
            f.write(f"    Detail      : {r['detail']}\n")
            f.write("-" * 72 + "\n\n")
    print(f"Log saved to: {log_file}")

    # --- per-group auth tallies (new/test group vs existing/active group) ---
    def _res(s):
        return s.rsplit(":", 1)[-1].strip() if s and ":" in s else (s or "-")

    def _tally(key):
        t = {}
        for r in results:
            if r["login"] != "OK":
                continue
            v = _res(r[key])
            t[v] = t.get(v, 0) + 1
        return t

    new_tally = _tally("test_res")        # primary group = override (NEW) when set
    old_tally = _tally("existing_result")  # existing/active login group
    ok = sum(1 for r in results if r["login"] == "OK")
    new_label = f"NEW/test group ({GROUP_OVERRIDE})" if GROUP_OVERRIDE else "active login group"

    print(f"\n{'='*60}\n  --- Overall verdict ---")
    for k in ("VALIDATED", "PASS_AMBIGUOUS", "PARTIAL", "AUTH_FAIL",
              "UNREACHABLE", "NEW_NOT_IN_GROUP", "NO_GROUP", "FAIL",
              "ERROR", "N/A"):
        if overall_counts.get(k):
            print(f"  {k:18}: {overall_counts[k]}")

    print(f"\n  --- {new_label} : auth result ---")
    for k in ("PASS", "AUTH_FAIL", "UNREACHABLE", "FAIL", "NO_GROUP", "-"):
        if new_tally.get(k):
            print(f"  {k:18}: {new_tally[k]} / {ok}")

    print(f"\n  --- existing/old login group : auth result ---")
    for k in ("PASS", "AUTH_FAIL", "UNREACHABLE", "FAIL", "NO_GROUP", "-"):
        if old_tally.get(k):
            print(f"  {k:18}: {old_tally[k]} / {ok}")

    mig_complete = sum(1 for r in results if r["migration"] == "COMPLETE")
    mig_incomplete = sum(1 for r in results if r["migration"] == "NOT_COMPLETE")
    print(f"\n  --- MIGRATION (new ISE servers in active group AND authenticated) ---")
    print(f"  COMPLETE          : {mig_complete} / {len(results)}")
    print(f"  NOT_COMPLETE      : {mig_incomplete} / {len(results)}")
    print(f"{'='*60}")
    print(f"Logged in OK: {ok}/{len(results)}  |  NEW group PASS: "
          f"{new_tally.get('PASS', 0)}  |  OLD group PASS: {old_tally.get('PASS', 0)}")
    print(f"  >> MIGRATION COMPLETE: {mig_complete}/{len(results)} devices <<")
    print(f"Total: {len(results)} | Time: {datetime.now() - start}")


if __name__ == "__main__":
    main()
