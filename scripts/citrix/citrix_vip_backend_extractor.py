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

install_if_missing(["requests"])

# ── Load shared config ─────────────────────────────────────────
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import config

import http.client
import base64
import json
import urllib.parse
import csv
import ssl
import socket
import ipaddress
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# ===== PATH SETUP =====
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, "..", ".."))
REPORTS_DIR = os.path.join(PROJECT_ROOT, "reports", "citrix")
os.makedirs(REPORTS_DIR, exist_ok=True)

# ===== Multiple Citrix ADC Load Balancers =====
LOAD_BALANCERS = [
    {'nsip': 'LCLDMZHER-CVL03', 'username': 'xx', 'password': 'xx'},
]

# ===== IP Range CSV for Location Mapping =====
IP_RANGE_FILE = config.IPAM_CSV_FILE

# ===== DNS Settings =====
MAX_DNS_WORKERS = 50
DNS_TIMEOUT = 1.0
socket.setdefaulttimeout(DNS_TIMEOUT)

# ===== OPTIMIZATION SETTINGS =====
ENABLE_DNS_RESOLUTION = True
ENABLE_PROGRESS_TRACKING = True
# Number of parallel workers for fetching vserver bindings within a single LB
BINDING_FETCH_WORKERS = 10
# Max concurrent connections per LB (controls socket pressure)
MAX_CONNECTIONS_PER_LB = 10


# ===== TLS Context for Legacy Devices =====
def make_legacy_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if hasattr(ssl, "OP_LEGACY_SERVER_CONNECT"):
        ctx.options |= ssl.OP_LEGACY_SERVER_CONNECT
    try:
        ctx.set_ciphers("DEFAULT:@SECLEVEL=1")
    except ssl.SSLError:
        pass
    return ctx


def tcp_reachable(host, port=443, timeout=5):
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        return True
    except Exception:
        return False


# ===== Thread-safe Connection Pool =====
import threading


class ThreadSafeConnectionPool:
    """
    Pool of reusable HTTP(S) connections for parallel API calls.
    Each thread gets its own connection via thread-local storage.
    """

    def __init__(self, nsip, username, password, use_https=True, max_requests_per_conn=100):
        self.nsip = nsip
        self.username = username
        self.password = password
        self.use_https = use_https
        self.max_requests_per_conn = max_requests_per_conn
        self._tls_context = make_legacy_context() if use_https else None
        self._local = threading.local()
        self._auth = base64.b64encode(f"{username}:{password}".encode()).decode()

    def _get_thread_conn(self):
        """Get or create a connection for the current thread."""
        conn = getattr(self._local, 'conn', None)
        count = getattr(self._local, 'count', 0)

        if conn is None or count >= self.max_requests_per_conn:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass
            if self.use_https:
                conn = http.client.HTTPSConnection(self.nsip, context=self._tls_context, timeout=60)
            else:
                conn = http.client.HTTPConnection(self.nsip, timeout=60)
            self._local.conn = conn
            self._local.count = 0

        return conn

    def execute(self, command, max_retries=3):
        """Execute an API GET request with retries. Thread-safe."""
        for attempt in range(max_retries):
            try:
                conn = self._get_thread_conn()
                headers = {
                    'Authorization': f'Basic {self._auth}',
                    'Content-Type': 'application/json',
                    'Connection': 'keep-alive',
                }
                conn.request("GET", command, headers=headers)
                response = conn.getresponse()
                data = response.read()
                self._local.count = getattr(self._local, 'count', 0) + 1

                if response.status != 200:
                    if attempt < max_retries - 1:
                        time.sleep(1)
                        continue
                    return None
                return data.decode()
            except Exception as e:
                # Reset connection on error
                self._local.conn = None
                self._local.count = 0
                if attempt < max_retries - 1:
                    time.sleep(2)
                else:
                    return None
        return None

    def close_all(self):
        """Close the current thread's connection (call from each thread or main)."""
        conn = getattr(self._local, 'conn', None)
        if conn:
            try:
                conn.close()
            except Exception:
                pass
            self._local.conn = None


def safe_json_loads(data):
    if not data:
        return {}
    try:
        return json.loads(data)
    except Exception:
        return {}


def read_ip_ranges_from_csv(file_path):
    print(f"[DEBUG] Reading IP ranges from: {file_path}")
    ip_ranges = []
    try:
        with open(file_path, mode='r', encoding='utf-8') as file:
            reader = csv.reader(file)
            next(reader)
            for row in reader:
                if len(row) < 4:
                    continue
                network_range = row[3].strip()
                block_name = row[2].strip()
                if network_range and block_name:
                    try:
                        ip_ranges.append((ipaddress.ip_network(network_range), block_name))
                    except ValueError:
                        pass
    except FileNotFoundError:
        print(f"[ERROR] IP range file not found: {file_path}")
    print(f"[DEBUG] Loaded {len(ip_ranges)} IP ranges")
    return ip_ranges


def get_location(ip, ip_ranges):
    try:
        ip_addr = ipaddress.ip_address(ip)
        for network, block_name in ip_ranges:
            if ip_addr in network:
                return block_name
    except ValueError:
        return ''
    return ''


def resolve_fqdn(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return 'Unresolved'


# ===========================================================================
# CORE OPTIMIZATION: Bulk-fetch lookup tables before processing vservers
# ===========================================================================

def bulk_fetch_servers(pool):
    """Fetch ALL server objects in one call → build name→IP map."""
    print(f"  [BULK] Fetching all servers...")
    data = pool.execute("/nitro/v1/config/server")
    servers = safe_json_loads(data).get('server', [])
    server_map = {}
    for s in servers:
        name = s.get('name', '')
        ip = s.get('ipaddress', 'N/A')
        if name:
            server_map[name] = ip
    print(f"  [BULK] Cached {len(server_map)} server name→IP mappings")
    return server_map


def bulk_fetch_services(pool):
    """Fetch ALL service objects in one call → build name→details map."""
    print(f"  [BULK] Fetching all services...")
    data = pool.execute("/nitro/v1/config/service")
    services = safe_json_loads(data).get('service', [])
    svc_map = {}
    for svc in services:
        name = svc.get('name', '')
        if name:
            svc_map[name] = {
                'ip': svc.get('ipaddress', 'N/A'),
                'port': svc.get('port', 'N/A'),
                'status': svc.get('svrstate', 'Unknown'),
                'servername': svc.get('servername', ''),
            }
    print(f"  [BULK] Cached {len(svc_map)} service details")
    return svc_map


def bulk_fetch_servicegroups(pool):
    """Fetch ALL service group objects."""
    print(f"  [BULK] Fetching all service groups...")
    data = pool.execute("/nitro/v1/config/servicegroup")
    sgs = safe_json_loads(data).get('servicegroup', [])
    sg_names = [sg.get('servicegroupname', '') for sg in sgs if sg.get('servicegroupname')]
    print(f"  [BULK] Found {len(sg_names)} service groups")
    return sg_names


def bulk_fetch_sg_members(pool, sg_names, server_map):
    """
    Fetch all service group member bindings in parallel.
    Returns: sg_name → [list of backend dicts]
    """
    print(f"  [BULK] Fetching member bindings for {len(sg_names)} service groups...")
    sg_member_map = {}

    def fetch_one_sg(sg_name):
        data = pool.execute(
            f"/nitro/v1/config/servicegroup_servicegroupmember_binding/{urllib.parse.quote(sg_name)}"
        )
        members_json = safe_json_loads(data)
        backends = []
        for member in members_json.get('servicegroup_servicegroupmember_binding', []):
            sname = member.get('servername', '')
            # Use pre-fetched server map instead of individual API calls
            ip = member.get('ip', server_map.get(sname, 'N/A'))
            if ip == '0.0.0.0' or not ip:
                ip = server_map.get(sname, 'N/A')
            backends.append({
                'name': sname,
                'ip': ip,
                'status': member.get('svrstate', 'Unknown'),
            })
        return sg_name, backends

    with ThreadPoolExecutor(max_workers=BINDING_FETCH_WORKERS) as executor:
        futures = {executor.submit(fetch_one_sg, name): name for name in sg_names}
        done = 0
        for future in as_completed(futures):
            sg_name, backends = future.result()
            sg_member_map[sg_name] = backends
            done += 1
            if done % 50 == 0:
                print(f"    [PROGRESS] Fetched {done}/{len(sg_names)} service group bindings")

    print(f"  [BULK] Cached members for {len(sg_member_map)} service groups")
    return sg_member_map


def bulk_fetch_cspolicies(pool):
    """Fetch ALL cspolicy objects → name→{rule, action} map (one call)."""
    print(f"  [BULK] Fetching all CS policies...")
    data = pool.execute("/nitro/v1/config/cspolicy")
    policies = safe_json_loads(data).get('cspolicy', [])
    cspolicy_map = {}
    for p in policies:
        name = p.get('policyname', '')
        if name:
            cspolicy_map[name] = {
                'rule': p.get('rule', ''),
                'action': p.get('action', ''),
            }
    print(f"  [BULK] Cached {len(cspolicy_map)} CS policies")
    return cspolicy_map


def bulk_fetch_csactions(pool):
    """Fetch ALL csaction objects → name→target LB vserver map (one call)."""
    print(f"  [BULK] Fetching all CS actions...")
    data = pool.execute("/nitro/v1/config/csaction")
    actions = safe_json_loads(data).get('csaction', [])
    csaction_map = {}
    for a in actions:
        name = a.get('name', '')
        if name:
            csaction_map[name] = a.get('targetlbvserver') or a.get('targetvserver', '')
    print(f"  [BULK] Cached {len(csaction_map)} CS actions")
    return csaction_map


# ===========================================================================
# Fetch vserver bindings in parallel using cached lookup tables
# ===========================================================================

def fetch_lb_vserver_bindings(pool, vserver, server_map, svc_map, sg_member_map):
    """
    Resolve backend servers for a single LB vserver using cached data.
    Only makes API calls for the binding list (sg_binding + svc_binding per vserver),
    NOT for individual server/service lookups.
    """
    vname = vserver.get('name', '')
    backend_servers = []

    # --- Service Group Bindings ---
    sg_data = pool.execute(
        f"/nitro/v1/config/lbvserver_servicegroup_binding/{urllib.parse.quote(vname)}"
    )
    sg_json = safe_json_loads(sg_data)
    for sg_binding in sg_json.get('lbvserver_servicegroup_binding', []):
        sg_name = sg_binding.get('servicegroupname', '')
        # Use pre-fetched SG member map
        if sg_name in sg_member_map:
            backend_servers.extend(sg_member_map[sg_name])
        else:
            # Fallback: fetch individually (shouldn't happen often)
            sg_info = pool.execute(
                f"/nitro/v1/config/servicegroup_servicegroupmember_binding/{urllib.parse.quote(sg_name)}"
            )
            sg_info_json = safe_json_loads(sg_info)
            for member in sg_info_json.get('servicegroup_servicegroupmember_binding', []):
                sname = member.get('servername', '')
                ip = server_map.get(sname, 'N/A')
                backend_servers.append({
                    'name': sname, 'ip': ip, 'status': member.get('svrstate', 'Unknown')
                })

    # --- Direct Service Bindings ---
    svc_data = pool.execute(
        f"/nitro/v1/config/lbvserver_service_binding/{urllib.parse.quote(vname)}"
    )
    svc_json = safe_json_loads(svc_data)
    for svc_binding in svc_json.get('lbvserver_service_binding', []):
        svc_name = svc_binding.get('servicename', '')
        # Use pre-fetched service map
        if svc_name in svc_map:
            info = svc_map[svc_name]
            backend_servers.append({
                'name': svc_name,
                'ip': info['ip'],
                'port': info['port'],
                'status': info['status'],
            })
        else:
            # Fallback: fetch individually
            svc_info = pool.execute(f"/nitro/v1/config/service/{urllib.parse.quote(svc_name)}")
            svc_info_json = safe_json_loads(svc_info)
            if 'service' in svc_info_json and svc_info_json['service']:
                s = svc_info_json['service'][0]
                backend_servers.append({
                    'name': svc_name,
                    'ip': s.get('ipaddress', 'N/A'),
                    'port': s.get('port', 'N/A'),
                    'status': s.get('svrstate', 'Unknown'),
                })

    return {
        'type': 'Load Balancing',
        'vserver_name': vname,
        'ipv46': vserver.get('ipv46', 'N/A'),
        'port': vserver.get('port', 'N/A'),
        'state': vserver.get('curstate', 'N/A'),
        'domains': '',
        'policy_rule': '', 'targetlbvserver': '', 'policy_action': '', 'targetvserver': '',
        'backend_servers': backend_servers,
    }


def _gslb_states(binding):
    """
    Pull the two states the ADC GUI shows for a GSLB backend:
      STATE           -> curstate  (configured/monitored state)
      EFFECTIVE STATE -> svreffgslbstate  (state after GSLB metric/threshold)
    Returns (state, effective_state); effective_state is '' if not reported.
    """
    state = binding.get('curstate') or binding.get('svrstate') or 'N/A'
    eff = binding.get('svreffgslbstate') or binding.get('effstate') or ''
    return state, eff


def fetch_gslb_vserver_bindings(pool, vserver):
    """
    Fetch GSLB vserver bindings (services + service-group members + domain).

    Captures BOTH the configured State (curstate) and the Effective State
    (svreffgslbstate) for every GSLB backend, matching the ADC GUI's
    'STATE' and 'EFFECTIVE STATE' columns. Effective state is carried on the
    backend as 'eff_status' and folded into the status column at write time.
    """
    vname = vserver.get('name', '')
    backend_servers = []
    domain_bindings = []

    # --- GSLB Services ---
    svc_data = pool.execute(
        f"/nitro/v1/config/gslbvserver_gslbservice_binding/{urllib.parse.quote(vname)}"
    )
    for b in safe_json_loads(svc_data).get('gslbvserver_gslbservice_binding', []):
        state, eff = _gslb_states(b)
        backend_servers.append({
            'name': b.get('servicename') or b.get('servername', 'N/A'),
            'ip': b.get('ipaddress', 'N/A'),
            'status': state,
            'eff_status': eff,
        })

    # --- GSLB Service Group Members ---
    sgm_data = pool.execute(
        f"/nitro/v1/config/gslbvserver_gslbservicegroupmember_binding/{urllib.parse.quote(vname)}"
    )
    for b in safe_json_loads(sgm_data).get('gslbvserver_gslbservicegroupmember_binding', []):
        state, eff = _gslb_states(b)
        backend_servers.append({
            'name': b.get('servername') or b.get('servicegroupname', 'N/A'),
            'ip': b.get('ip') or b.get('ipaddress', 'N/A'),
            'status': state,
            'eff_status': eff,
        })

    dom_data = pool.execute(
        f"/nitro/v1/config/gslbvserver_domain_binding/{urllib.parse.quote(vname)}"
    )
    for d in safe_json_loads(dom_data).get('gslbvserver_domain_binding', []):
        domain_bindings.append(d.get('domainname', ''))

    return {
        'type': 'GSLB',
        'vserver_name': vname,
        'ipv46': vserver.get('ipv46', 'N/A'),
        'port': vserver.get('port', 'N/A'),
        'state': vserver.get('curstate', 'N/A'),
        'domains': ', '.join(domain_bindings),
        'policy_rule': '', 'targetlbvserver': '', 'policy_action': '', 'targetvserver': '',
        'backend_servers': backend_servers,
    }


def fetch_cs_vserver_bindings(pool, csserver, cspolicy_map=None, csaction_map=None,
                              vserver_state_map=None):
    """
    Fetch ALL CS policy bindings for a CS vserver (not just the first).

    Each policy has its own target LB, so we walk every bound policy — sorted
    by priority — and resolve, per policy:
        rule       (from cspolicy)
        action     (from cspolicy)
        target LB  (binding.targetlbvserver, else csaction.targetvserver)
        target vs  (csaction.targetvserver)
        target LB status (that target LB vserver's UP/DOWN state)

    The policy columns are folded into one CS row: each column is a
    newline-separated list, aligned so policy N's rule / target LB / action /
    target vserver / target-LB-status share the same line. Uses pre-fetched
    cspolicy/csaction/vserver-state maps to avoid per-policy API calls.
    """
    cspolicy_map = cspolicy_map or {}
    csaction_map = csaction_map or {}
    vserver_state_map = vserver_state_map or {}
    vname = csserver.get('name', '')

    cs_data = pool.execute(
        f"/nitro/v1/config/csvserver_binding/{urllib.parse.quote(vname)}"
    )
    cs_json = safe_json_loads(cs_data)
    binding_list = cs_json.get('csvserver_binding') or [{}]
    binding_info = binding_list[0] if binding_list else {}
    policy_bindings = binding_info.get('csvserver_cspolicy_binding', [])
    # Default LB vserver binding — traffic matching NO policy goes here. CS
    # vservers with zero policies bound route ALL traffic to this default LB.
    default_lb_bindings = binding_info.get('csvserver_lbvserver_binding', [])

    # Sort by priority so the aligned lists read top-to-bottom in bind order
    def _prio(b):
        try:
            return int(b.get('priority', 0))
        except (TypeError, ValueError):
            return 0
    policy_bindings = sorted(policy_bindings, key=_prio)

    rules, target_lbs, actions, target_vs, target_lb_status = [], [], [], [], []
    for binding in policy_bindings:
        policy_name = binding.get('policyname', '')
        direct_lb = binding.get('targetlbvserver', '')

        # Resolve rule + action from cache (fall back to a single lookup)
        info = cspolicy_map.get(policy_name)
        if info is None and policy_name:
            pj = safe_json_loads(
                pool.execute(f"/nitro/v1/config/cspolicy/{urllib.parse.quote(policy_name)}"))
            plist = pj.get('cspolicy', [])
            info = {'rule': plist[0].get('rule', ''), 'action': plist[0].get('action', '')} if plist else {}
        info = info or {}
        rule = info.get('rule', '')
        action = info.get('action', '')

        # Resolve the action's target from cache (fall back to a single lookup)
        action_target = ''
        if action:
            if action in csaction_map:
                action_target = csaction_map[action]
            else:
                aj = safe_json_loads(
                    pool.execute(f"/nitro/v1/config/csaction/{urllib.parse.quote(action)}"))
                alist = aj.get('csaction', [])
                if alist:
                    action_target = alist[0].get('targetlbvserver') or alist[0].get('targetvserver', '')

        this_lb = direct_lb or action_target            # each policy's LB
        rules.append(rule)
        target_lbs.append(this_lb)
        actions.append(action)
        target_vs.append(action_target)
        target_lb_status.append(vserver_state_map.get(this_lb, '') if this_lb else '')

    # --- Default LB vserver (catch-all) ---
    # Emitted as the last line of the folded lists with rule '(default)'.
    # For CS vservers with no policies at all (e.g. Kubernetes ingress-style
    # CS), this is the ONLY target — previously these rows came out blank.
    for b in default_lb_bindings:
        dlb = b.get('lbvserver', '')
        if not dlb:
            continue
        rules.append('(default)')
        target_lbs.append(dlb)
        actions.append('')
        target_vs.append('')
        target_lb_status.append(vserver_state_map.get(dlb, ''))

    return {
        'type': 'Content Switching',
        'vserver_name': vname,
        'ipv46': csserver.get('ipv46', 'N/A'),
        'port': csserver.get('port', 'N/A'),
        'state': csserver.get('curstate', 'N/A'),
        'domains': '',
        'policy_rule': '\n'.join(rules),
        'targetlbvserver': '\n'.join(target_lbs),
        'policy_action': '\n'.join(actions),
        'targetvserver': '\n'.join(target_vs),
        'targetlbstatus': '\n'.join(target_lb_status),
        'backend_servers': [],
    }


def process_simple_vserver(vserver, vtype):
    """Process CR and VPN vservers (no additional API calls needed)."""
    ip_address = vserver.get('ipv46', 'N/A')
    if not ip_address or ip_address == 'N/A':
        ip_val = vserver.get('ipaddress') or vserver.get('ip')
        if ip_val and ip_val != '0.0.0.0':
            ip_address = ip_val

    status = vserver.get('curstate') or vserver.get('state', 'N/A')
    if vtype == 'VPN':
        status = status or vserver.get('vsvr_state', 'N/A')

    target = ''
    if vtype == 'Cache Redirection':
        target = vserver.get('targetlbvserver', '')
    elif vtype == 'VPN':
        target = vserver.get('csvip_name', '')

    return {
        'type': vtype,
        'vserver_name': vserver.get('name', ''),
        'ipv46': ip_address,
        'port': vserver.get('port', 'N/A'),
        'state': status,
        'domains': '',
        'policy_rule': '',
        'targetlbvserver': target if vtype == 'Cache Redirection' else '',
        'policy_action': '',
        'targetvserver': target if vtype == 'VPN' else '',
        'backend_servers': [],
    }


def count_status(vservers, state_field='curstate', fallback_fields=None):
    """Count UP/DOWN/OOS/Other for a list of vserver dicts."""
    up = down = oos = other = 0
    for v in vservers:
        s = v.get(state_field, '')
        if not s and fallback_fields:
            for f in fallback_fields:
                s = v.get(f, '')
                if s:
                    break
        s = s.upper() if s else ''
        if s == 'UP':
            up += 1
        elif s == 'DOWN':
            down += 1
        elif s == 'OUT OF SERVICE':
            oos += 1
        else:
            other += 1
    return {'total': len(vservers), 'up': up, 'down': down, 'oos': oos, 'other': other}


# ===========================================================================
# Main per-LB processing function
# ===========================================================================

def process_load_balancer(lb_config, ip_ranges):
    nsip = lb_config['nsip']
    username = lb_config['username']
    password = lb_config['password']

    print(f"\n{'=' * 80}")
    print(f"[INFO] Processing Load Balancer: {nsip}")
    print(f"{'=' * 80}")

    # Check reachability first
    if not tcp_reachable(nsip, 443, timeout=5):
        print(f"[ERROR] {nsip} is not reachable on port 443, skipping.")
        return None

    pool = ThreadSafeConnectionPool(nsip, username, password)
    start_time = time.time()

    try:
        # ---------------------------------------------------------------
        # PHASE 1: Bulk-fetch all vservers (5 sequential calls - fast)
        # ---------------------------------------------------------------
        print(f"\n[PHASE 1] Fetching all vserver lists...")

        lb_data = safe_json_loads(pool.execute("/nitro/v1/config/lbvserver"))
        gslb_data = safe_json_loads(pool.execute("/nitro/v1/config/gslbvserver"))
        cs_data = safe_json_loads(pool.execute("/nitro/v1/config/csvserver"))
        cr_data = safe_json_loads(pool.execute("/nitro/v1/config/crvserver"))
        vpn_data = safe_json_loads(pool.execute("/nitro/v1/config/vpnvserver"))

        lb_list = lb_data.get('lbvserver', [])
        gslb_list = gslb_data.get('gslbvserver', [])
        cs_list = cs_data.get('csvserver', [])
        cr_list = cr_data.get('crvserver', [])
        vpn_list = vpn_data.get('vpnvserver', [])

        total_vs = len(lb_list) + len(gslb_list) + len(cs_list) + len(cr_list) + len(vpn_list)
        print(f"  Found: LB={len(lb_list)}, GSLB={len(gslb_list)}, CS={len(cs_list)}, "
              f"CR={len(cr_list)}, VPN={len(vpn_list)} → Total={total_vs}")

        # Map every vserver name -> its VIP status, so a CS policy's target LB
        # can be annotated with that LB's UP/DOWN state. LB added last so it
        # wins any name collision (CS policies target LB vservers).
        vserver_state_map = {}
        for vlist in (cr_list, vpn_list, gslb_list, cs_list, lb_list):
            for v in vlist:
                name = v.get('name', '')
                if name:
                    vserver_state_map[name] = (
                        v.get('curstate') or v.get('state') or v.get('vsvr_state') or 'N/A')

        # ---------------------------------------------------------------
        # PHASE 2: Bulk-fetch lookup tables (3 calls + parallel SG members)
        # This is the KEY optimization — replaces thousands of per-vserver calls
        # ---------------------------------------------------------------
        print(f"\n[PHASE 2] Building lookup caches...")
        t2 = time.time()

        server_map = bulk_fetch_servers(pool)
        svc_map = bulk_fetch_services(pool)
        sg_names = bulk_fetch_servicegroups(pool)
        sg_member_map = bulk_fetch_sg_members(pool, sg_names, server_map)
        cspolicy_map = bulk_fetch_cspolicies(pool)
        csaction_map = bulk_fetch_csactions(pool)

        print(f"  [PHASE 2] Lookup caches built in {time.time() - t2:.1f}s")

        # ---------------------------------------------------------------
        # PHASE 3: Process vserver bindings in parallel
        # ---------------------------------------------------------------
        bindings_info = []
        all_ips = set()
        max_backends = 0

        # --- 3a: LB vservers (parallel — these need binding API calls) ---
        print(f"\n[PHASE 3a] Processing {len(lb_list)} LB vserver bindings (parallel)...")
        t3 = time.time()

        with ThreadPoolExecutor(max_workers=BINDING_FETCH_WORKERS) as executor:
            futures = {
                executor.submit(
                    fetch_lb_vserver_bindings, pool, vs, server_map, svc_map, sg_member_map
                ): vs for vs in lb_list
            }
            done = 0
            for future in as_completed(futures):
                info = future.result()
                bindings_info.append(info)
                for b in info['backend_servers']:
                    if b['ip'] != 'N/A':
                        all_ips.add(b['ip'])
                max_backends = max(max_backends, len(info['backend_servers']))
                done += 1
                if done % 200 == 0:
                    print(f"    [PROGRESS] {done}/{len(lb_list)} LB vservers processed")

        print(f"  LB vservers done in {time.time() - t3:.1f}s")

        # --- 3b: GSLB vservers (parallel) ---
        print(f"\n[PHASE 3b] Processing {len(gslb_list)} GSLB vserver bindings (parallel)...")
        t3b = time.time()

        with ThreadPoolExecutor(max_workers=BINDING_FETCH_WORKERS) as executor:
            futures = {
                executor.submit(fetch_gslb_vserver_bindings, pool, vs): vs for vs in gslb_list
            }
            for future in as_completed(futures):
                info = future.result()
                bindings_info.append(info)
                for b in info['backend_servers']:
                    if b['ip'] != 'N/A':
                        all_ips.add(b['ip'])
                max_backends = max(max_backends, len(info['backend_servers']))

        print(f"  GSLB vservers done in {time.time() - t3b:.1f}s")

        # --- 3c: CS vservers (parallel) ---
        print(f"\n[PHASE 3c] Processing {len(cs_list)} CS vserver bindings (parallel)...")
        t3c = time.time()

        with ThreadPoolExecutor(max_workers=BINDING_FETCH_WORKERS) as executor:
            futures = {
                executor.submit(fetch_cs_vserver_bindings, pool, vs,
                                cspolicy_map, csaction_map, vserver_state_map): vs
                for vs in cs_list
            }
            for future in as_completed(futures):
                bindings_info.append(future.result())

        print(f"  CS vservers done in {time.time() - t3c:.1f}s")

        # --- 3d: CR and VPN vservers (no API calls needed, instant) ---
        print(f"\n[PHASE 3d] Processing {len(cr_list)} CR + {len(vpn_list)} VPN vservers...")
        for cr in cr_list:
            bindings_info.append(process_simple_vserver(cr, 'Cache Redirection'))
        for vpn in vpn_list:
            bindings_info.append(process_simple_vserver(vpn, 'VPN'))

        # ---------------------------------------------------------------
        # PHASE 4: DNS Resolution (parallel)
        # ---------------------------------------------------------------
        ip_to_fqdn = {}
        if ENABLE_DNS_RESOLUTION and all_ips:
            print(f"\n[PHASE 4] Resolving {len(all_ips)} unique IPs...")
            t4 = time.time()
            with ThreadPoolExecutor(max_workers=MAX_DNS_WORKERS) as executor:
                future_to_ip = {executor.submit(resolve_fqdn, ip): ip for ip in all_ips}
                resolved = 0
                for future in as_completed(future_to_ip):
                    ip = future_to_ip[future]
                    ip_to_fqdn[ip] = future.result()
                    resolved += 1
                    if resolved % 200 == 0:
                        print(f"    [PROGRESS] Resolved {resolved}/{len(all_ips)} IPs")
            print(f"  DNS resolution done in {time.time() - t4:.1f}s")
        else:
            for ip in all_ips:
                ip_to_fqdn[ip] = 'Unresolved'

        # ---------------------------------------------------------------
        # PHASE 5: Enrich with FQDN + Location, compute stats
        # ---------------------------------------------------------------
        backend_up = backend_down = backend_oos = backend_other = 0
        for info in bindings_info:
            for backend in info['backend_servers']:
                backend['fqdn'] = ip_to_fqdn.get(backend['ip'], 'Unresolved')
                backend['location'] = get_location(backend['ip'], ip_ranges)
                status = backend.get('status', '').upper()
                if status == 'UP':
                    backend_up += 1
                elif status == 'DOWN':
                    backend_down += 1
                elif status == 'OUT OF SERVICE':
                    backend_oos += 1
                else:
                    backend_other += 1

        # Compute vserver status counts
        lb_stats = count_status(lb_list)
        gslb_stats = count_status(gslb_list)
        cs_stats = count_status(cs_list)
        cr_stats = count_status(cr_list, fallback_fields=['state'])
        vpn_stats = count_status(vpn_list, fallback_fields=['state', 'vsvr_state'])

        elapsed = time.time() - start_time
        total_backends = backend_up + backend_down + backend_oos + backend_other

        print(f"\n[SUCCESS] Completed {nsip} in {elapsed:.1f}s ({elapsed / 60:.1f} min)")
        print(f"  vServers: {total_vs} | Backends: {total_backends} | Unique IPs: {len(all_ips)}")
        print(f"  Backend Status → UP: {backend_up}, DOWN: {backend_down}, OOS: {backend_oos}, Other: {backend_other}")

        return {
            'nsip': nsip,
            'bindings_info': bindings_info,
            'max_backends': max_backends,
            'stats': {
                'lb': lb_stats, 'gslb': gslb_stats, 'cs': cs_stats, 'cr': cr_stats, 'vpn': vpn_stats,
                'total_vservers': total_vs,
                'total_up': lb_stats['up'] + gslb_stats['up'] + cs_stats['up'] + cr_stats['up'] + vpn_stats['up'],
                'total_down': lb_stats['down'] + gslb_stats['down'] + cs_stats['down'] + cr_stats['down'] + vpn_stats['down'],
                'total_oos': lb_stats['oos'] + gslb_stats['oos'] + cs_stats['oos'] + cr_stats['oos'] + vpn_stats['oos'],
                'unique_ips': len(all_ips),
                'processing_time': elapsed,
                'backend_up': backend_up, 'backend_down': backend_down,
                'backend_oos': backend_oos, 'backend_other': backend_other,
                'total_backends': total_backends,
            }
        }

    finally:
        pool.close_all()


# ===========================================================================
# CSV Output (unchanged logic, minor cleanup)
# ===========================================================================

def write_csv_streaming(output_file, all_results, global_max_backends):
    print(f"\n[INFO] Writing output to {output_file}")

    with open(output_file, mode='w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)

        header = [
            'Owner Group', 'Contact', 'Status', 'Change Date', 'Change Record', 'PPS Family',
            'Support', 'Tech Lead', 'PM', 'PPS Lead', 'VP', 'Application',
            'VPX', 'Type of Virtual Server', 'Virtual Server Name', 'Virtual Server IP',
            'Virtual Server Port', 'VIP Status', 'Redundancy', 'Progress Summary', 'GSLB Domain',
        ]
        for i in range(1, global_max_backends + 1):
            header += [f'BackendName{i}', f'BackendIP{i}', f'BackendHost_FQDN{i}',
                       f'BackendStatus{i}', f'BackendLocation{i}']
        header += ['Policy Rule', 'Target LB VServer', 'Policy Action', 'Target VServer',
                   'Target LB Status']
        writer.writerow(header)

        total_rows = 0
        # Group by type within each VPX for consistent ordering
        type_order = ['Load Balancing', 'GSLB', 'Content Switching', 'Cache Redirection', 'VPN']

        for result in all_results:
            for vtype in type_order:
                for info in result['bindings_info']:
                    if info['type'] != vtype:
                        continue
                    row = [''] * 12  # Placeholder columns (Owner Group thru Application)
                    row += [
                        result['nsip'], info['type'], info['vserver_name'],
                        info['ipv46'], info['port'], info['state'], '', '', info['domains'],
                    ]
                    for backend in info['backend_servers']:
                        # For GSLB backends, show 'STATE / EFFECTIVE STATE'
                        # (e.g. 'DOWN / DOWN'); LB backends keep a plain status.
                        eff = backend.get('eff_status', '')
                        status_disp = f"{backend['status']} / {eff}" if eff else backend['status']
                        row += [backend['name'], backend['ip'], backend.get('fqdn', ''),
                                status_disp, backend.get('location', '')]
                    remaining = global_max_backends - len(info['backend_servers'])
                    row += [''] * (remaining * 5)
                    row += [info['policy_rule'], info['targetlbvserver'],
                            info['policy_action'], info['targetvserver'],
                            info.get('targetlbstatus', '')]
                    writer.writerow(row)
                    total_rows += 1

    return total_rows


# ===========================================================================
# Summary Report (unchanged logic)
# ===========================================================================

def write_summary_report(all_results, output_file, total_time):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = []
    lines.append("=" * 100)
    lines.append("CITRIX ADC LOAD BALANCER EXTRACTION SUMMARY REPORT")
    lines.append("=" * 100)
    lines.append(f"\nGenerated: {timestamp}")
    lines.append(f"Total Load Balancers Processed: {len(all_results)}")
    lines.append(f"Total Processing Time: {total_time / 60:.2f} minutes\n")

    # Aggregate stats
    totals = {k: 0 for k in [
        'lb', 'gslb', 'cs', 'cr', 'vpn',
        'backend_up', 'backend_down', 'backend_oos', 'backend_other', 'total_backends', 'unique_ips',
    ]}
    type_ups = {t: 0 for t in ['lb', 'gslb', 'cs', 'cr', 'vpn']}
    type_downs = {t: 0 for t in ['lb', 'gslb', 'cs', 'cr', 'vpn']}
    type_oos_counts = {t: 0 for t in ['lb', 'gslb', 'cs', 'cr', 'vpn']}

    for r in all_results:
        s = r.get('stats', {})
        for t in ['lb', 'gslb', 'cs', 'cr', 'vpn']:
            ts = s.get(t, {})
            totals[t] += ts.get('total', 0)
            type_ups[t] += ts.get('up', 0)
            type_downs[t] += ts.get('down', 0)
            type_oos_counts[t] += ts.get('oos', 0)
        totals['total_backends'] += s.get('total_backends', 0)
        totals['backend_up'] += s.get('backend_up', 0)
        totals['backend_down'] += s.get('backend_down', 0)
        totals['backend_oos'] += s.get('backend_oos', 0)
        totals['backend_other'] += s.get('backend_other', 0)
        totals['unique_ips'] += s.get('unique_ips', 0)

    grand_total_vs = sum(totals[t] for t in ['lb', 'gslb', 'cs', 'cr', 'vpn'])
    lines.append(f"Total Virtual Servers: {grand_total_vs:,}")
    lines.append(f"Total Backend Servers: {totals['total_backends']:,}")
    lines.append(f"Total Unique Backend IPs: {totals['unique_ips']:,}\n")

    for t, label in [('lb', 'Load Balancing'), ('gslb', 'GSLB'), ('cs', 'Content Switching'),
                     ('cr', 'Cache Redirection'), ('vpn', 'VPN')]:
        lines.append(f"  {label:<28} {totals[t]:>6,}  "
                     f"(UP: {type_ups[t]:>4}, DOWN: {type_downs[t]:>4}, OOS: {type_oos_counts[t]:>4})")

    if totals['total_backends'] > 0:
        tb = totals['total_backends']
        lines.append(f"\nBackend Health:")
        lines.append(f"  UP: {totals['backend_up']:>6} ({totals['backend_up'] / tb * 100:.1f}%)")
        lines.append(f"  DOWN: {totals['backend_down']:>6} ({totals['backend_down'] / tb * 100:.1f}%)")
        lines.append(f"  OOS: {totals['backend_oos']:>6} ({totals['backend_oos'] / tb * 100:.1f}%)")
        lines.append(f"  Other: {totals['backend_other']:>6} ({totals['backend_other'] / tb * 100:.1f}%)")

    # Per-LB details
    lines.append(f"\n{'=' * 100}")
    lines.append("INDIVIDUAL LOAD BALANCER DETAILS")
    lines.append("-" * 100)
    for idx, r in enumerate(all_results, 1):
        s = r.get('stats', {})
        lines.append(f"\n[{idx}] {r['nsip']}")
        for t, label in [('lb', 'LB'), ('gslb', 'GSLB'), ('cs', 'CS'), ('cr', 'CR'), ('vpn', 'VPN')]:
            ts = s.get(t, {})
            lines.append(f"    {label:<6} {ts.get('total', 0):>5} (UP:{ts.get('up', 0):>4} DOWN:{ts.get('down', 0):>4} OOS:{ts.get('oos', 0):>4})")
        lines.append(f"    Backends: {s.get('total_backends', 0)} | IPs: {s.get('unique_ips', 0)} | Time: {s.get('processing_time', 0):.1f}s")

    lines.append(f"\n{'=' * 100}")
    lines.append(f"CSV: {output_file}")
    lines.append("=" * 100)

    report_file = output_file.replace('.csv', '_summary_report.txt')
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))
    print('\n'.join(lines))
    return report_file


# ===========================================================================
# Main
# ===========================================================================

def main():
    overall_start = time.time()

    print("=" * 80)
    print("CITRIX MULTI-LB EXTRACTOR v5 - OPTIMIZED")
    print("=" * 80)
    print(f"  Load Balancers: {len(LOAD_BALANCERS)}")
    print(f"  DNS Resolution: {'ON' if ENABLE_DNS_RESOLUTION else 'OFF'}")
    print(f"  Parallel Binding Workers: {BINDING_FETCH_WORKERS}")

    ip_ranges = read_ip_ranges_from_csv(IP_RANGE_FILE)

    all_results = []
    global_max_backends = 0

    for lb_idx, lb_config in enumerate(LOAD_BALANCERS, 1):
        try:
            print(f"\n{'#' * 80}")
            print(f"LOAD BALANCER {lb_idx}/{len(LOAD_BALANCERS)}")
            print(f"{'#' * 80}")

            result = process_load_balancer(lb_config, ip_ranges)
            if result is None:
                continue
            all_results.append(result)
            global_max_backends = max(global_max_backends, result['max_backends'])

            elapsed = time.time() - overall_start
            avg = elapsed / lb_idx
            remaining = avg * (len(LOAD_BALANCERS) - lb_idx)
            print(f"\n  Progress: {lb_idx}/{len(LOAD_BALANCERS)} | "
                  f"Elapsed: {elapsed / 60:.1f}m | ETA: {remaining / 60:.1f}m")

        except Exception as e:
            print(f"[ERROR] Failed {lb_config['nsip']}: {e}")
            import traceback
            traceback.print_exc()

    # Write output
    output_file = os.path.join(REPORTS_DIR, "combined_load_balancers.csv")
    total_rows = write_csv_streaming(output_file, all_results, global_max_backends)
    total_time = time.time() - overall_start

    print(f"\n{'=' * 80}")
    print(f"DONE — {output_file}")
    print(f"  LBs: {len(all_results)} | Rows: {total_rows:,} | Max backends: {global_max_backends}")
    print(f"  Total time: {total_time / 60:.1f} minutes")
    print(f"{'=' * 80}")

    write_summary_report(all_results, output_file, total_time)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[INFO] Interrupted by user")
    except Exception as e:
        print(f"\n[ERROR] {e}")
        import traceback
        traceback.print_exc()