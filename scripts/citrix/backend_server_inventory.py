"""
backend_server_inventory.py

Builds a backend-server-centric inventory from the LB VIP master workbook:

    ONE ROW PER BACKEND SERVER, chained upward through the front door:

        Backend Server -> LB VIP -> CS VIP -> GSLB (domain) -> Owner / Application

    - Backends live only on 'Load Balancing' rows (BackendName1..N blocks).
    - CS rows attach to an LB via 'Target LB VServer' / 'Target VServer'.
    - GSLB rows attach to a VIP because their gslb-service IPs ARE the
      LB/CS VIP IPs; their 'GSLB Domain' is the public name.
    - Owner Group / Application / contacts are resolved by walking the chain:
      take them from the LB row if filled, else the CS row, else the GSLB row.
      The 'Owner Source' column records which row supplied them.

Reads the master workbook (NOT the ADCs) and does not modify it. The Citrix
extractor script is untouched; this is a standalone transform.

Usage:
    python backend_server_inventory.py [path\\to\\LB VIP Inventory_Master.xlsx] [output.csv]

If no path is given, known default locations are tried. If the workbook is
locked (open in Excel), a temp copy is read instead.
"""

import sys
import os
import re
import csv
import shutil
import subprocess
import importlib
import tempfile
from datetime import datetime
from collections import defaultdict


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


install_if_missing(["openpyxl"])
import openpyxl


# ===== PATH SETUP =====
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, "..", ".."))
REPORTS_DIR = os.path.join(PROJECT_ROOT, "reports", "citrix")

MASTER_SHEET_NAME = "Master Inventory-Use this sheet"

# Candidate locations for the master workbook, tried in order
DEFAULT_MASTER_CANDIDATES = [
    os.path.join(REPORTS_DIR, "LB VIP Inventory_Master.xlsx"),
    os.path.join(PROJECT_ROOT, "LB VIP Inventory_Master.xlsx"),
]

# Enrichment columns carried through from the master (in output order).
# Resolved by chain-walk: LB row -> CS row -> GSLB row.
ENRICH_COLS = [
    'Owner Group', 'Contact', 'Application', 'PPS Family',
    'Support', 'Tech Lead', 'PM', 'PPS Lead', 'VP',
    'Status', 'Change Date', 'Change Record',
]

OUTPUT_HEADER = (
    ['Backend Server Name', 'Backend IP', 'Backend FQDN',
     'Backend Status', 'Backend Location',
     'VPX', 'LB VServer Name', 'LB VIP IP', 'LB VIP Port', 'LB VIP Status',
     'CS VServer Name', 'CS VIP IP', 'CS VIP Port', 'CS VIP Status',
     'GSLB VServer Name', 'GSLB Domain']
    + ENRICH_COLS
    + ['Owner Source']
)


def clean(val):
    """Normalize a cell value to a stripped string ('' for None/N/A noise)."""
    if val is None:
        return ''
    s = str(val).strip()
    if s.upper() in ('N/A', 'NONE', 'NULL'):
        return ''
    return s


def open_master_workbook(path):
    """
    Open the master workbook read-only. If it's locked (open in Excel /
    OneDrive sync), fall back to reading a temp copy.
    """
    try:
        return openpyxl.load_workbook(path, read_only=True, data_only=True), None
    except PermissionError:
        print("[WARN] Workbook is locked (open in Excel?). Reading a temp copy...")
        tmp = os.path.join(tempfile.gettempdir(),
                           f"_bsi_copy_{os.getpid()}_" + os.path.basename(path))
        shutil.copy2(path, tmp)
        return openpyxl.load_workbook(tmp, read_only=True, data_only=True), tmp


def find_header_row(ws, probe_rows=10):
    """
    Locate the real header row (row 3 in the master, but detect it instead of
    hardcoding): the first row containing 'Virtual Server Name'.
    Returns (row_index, {column_name: column_index_0based}).
    """
    for r_idx, row in enumerate(ws.iter_rows(min_row=1, max_row=probe_rows,
                                             values_only=True), start=1):
        cells = [clean(c) for c in row]
        if 'Virtual Server Name' in cells:
            col_map = {}
            for c_idx, name in enumerate(cells):
                if name and name not in col_map:
                    col_map[name] = c_idx
            return r_idx, col_map
    raise RuntimeError(
        f"Could not find header row (no 'Virtual Server Name' column in the "
        f"first {probe_rows} rows of sheet '{ws.title}')."
    )


def find_backend_blocks(col_map):
    """
    Discover BackendName1..N / BackendIP{i} / BackendHost_FQDN{i} /
    BackendStatus{i} / BackendLocation{i} column groups from the header.
    Returns a list of dicts sorted by backend index.
    """
    blocks = {}
    pat = re.compile(r'^BackendName(\d+)$')
    for name, idx in col_map.items():
        m = pat.match(name)
        if not m:
            continue
        i = int(m.group(1))
        blocks[i] = {
            'name': idx,
            'ip': col_map.get(f'BackendIP{i}'),
            'fqdn': col_map.get(f'BackendHost_FQDN{i}'),
            'status': col_map.get(f'BackendStatus{i}'),
            'location': col_map.get(f'BackendLocation{i}'),
        }
    return [blocks[i] for i in sorted(blocks)]


def cell(row, idx):
    if idx is None or idx >= len(row):
        return ''
    return clean(row[idx])


def load_master_rows(ws, header_row, col_map, backend_blocks):
    """
    Read every data row into a normalized dict:
      {vpx, type, name, ip, port, state, gslb_domain, target_lb, target_vs,
       enrich: {col: val}, backends: [{name, ip, fqdn, status, location}]}
    """
    g = lambda row, name: cell(row, col_map.get(name))
    rows = []
    for row in ws.iter_rows(min_row=header_row + 1, values_only=True):
        name = cell(row, col_map.get('Virtual Server Name'))
        if not name:
            continue
        backends = []
        for blk in backend_blocks:
            bname = cell(row, blk['name'])
            bip = cell(row, blk['ip'])
            if not bname and not bip:
                continue
            backends.append({
                'name': bname,
                'ip': bip,
                'fqdn': cell(row, blk['fqdn']),
                'status': cell(row, blk['status']),
                'location': cell(row, blk['location']),
            })
        rows.append({
            'vpx': g(row, 'VPX'),
            'type': g(row, 'Type of Virtual Server'),
            'name': name,
            'ip': g(row, 'Virtual Server IP'),
            'port': g(row, 'Virtual Server Port'),
            'state': g(row, 'VIP Status'),
            'gslb_domain': g(row, 'GSLB Domain'),
            'target_lb': g(row, 'Target LB VServer'),
            'target_vs': g(row, 'Target VServer'),
            'enrich': {c: g(row, c) for c in ENRICH_COLS},
            'backends': backends,
        })
    return rows


def build_indexes(rows):
    """
    Build the chain-lookup indexes:
      cs_by_target[(vpx, lb_vserver_name)] -> [CS rows targeting that LB]
      gslb_by_vip_ip[vip_ip]               -> [GSLB rows whose services hit that IP]
    A GSLB vserver's 'backends' are its gslb services, whose IPs are the
    LB/CS VIP IPs on the ADCs — that IP match is the GSLB->VIP join.
    """
    cs_by_target = defaultdict(list)
    gslb_by_vip_ip = defaultdict(list)
    for r in rows:
        rtype = r['type']
        if rtype == 'Content Switching':
            for tgt in (r['target_lb'], r['target_vs']):
                if tgt:
                    cs_by_target[(r['vpx'], tgt)].append(r)
        elif rtype == 'GSLB':
            for b in r['backends']:
                if b['ip'] and b['ip'] != '0.0.0.0':
                    gslb_by_vip_ip[b['ip']].append(r)
    return cs_by_target, gslb_by_vip_ip


def resolve_enrichment(chain_rows):
    """
    Walk the chain (LB row first, then CS rows, then GSLB rows) and take each
    enrichment column from the first row that has it filled. Owner Source
    reports where 'Owner Group' (or, failing that, 'Application') came from.
    """
    resolved = {c: '' for c in ENRICH_COLS}
    source = ''
    for label, r in chain_rows:
        if r is None:
            continue
        for c in ENRICH_COLS:
            if not resolved[c] and r['enrich'].get(c):
                resolved[c] = r['enrich'][c]
                if not source and c in ('Owner Group', 'Application'):
                    source = label
    return resolved, source


def join_unique(values):
    seen = []
    for v in values:
        if v and v not in seen:
            seen.append(v)
    return '; '.join(seen)


def build_backend_inventory(rows):
    """Emit one output row per backend server on every Load Balancing vserver."""
    cs_by_target, gslb_by_vip_ip = build_indexes(rows)

    out_rows = []
    stats = {
        'lb_vservers': 0, 'lb_no_backends': 0, 'backend_rows': 0,
        'with_cs': 0, 'with_gslb': 0, 'with_owner': 0, 'with_app': 0,
        'unique_backend_ips': set(),
    }

    for lb in rows:
        if lb['type'] != 'Load Balancing':
            continue
        stats['lb_vservers'] += 1

        # --- CS vservers pointing at this LB (same VPX) ---
        cs_rows = cs_by_target.get((lb['vpx'], lb['name']), [])

        # --- GSLB vservers whose services hit the LB VIP or the CS VIP ---
        gslb_rows = []
        candidate_vips = [lb['ip']] + [c['ip'] for c in cs_rows]
        for vip in candidate_vips:
            if vip and vip != '0.0.0.0':
                for g in gslb_by_vip_ip.get(vip, []):
                    if g not in gslb_rows:
                        gslb_rows.append(g)

        chain = ([('LB', lb)]
                 + [('CS', c) for c in cs_rows]
                 + [('GSLB', g) for g in gslb_rows])
        enrich, owner_source = resolve_enrichment(chain)

        cs_name = join_unique(c['name'] for c in cs_rows)
        cs_ip = join_unique(c['ip'] for c in cs_rows)
        cs_port = join_unique(c['port'] for c in cs_rows)
        cs_state = join_unique(c['state'] for c in cs_rows)
        gslb_name = join_unique(g['name'] for g in gslb_rows)
        gslb_domain = join_unique(g['gslb_domain'] for g in gslb_rows)

        base = ([lb['vpx'], lb['name'], lb['ip'], lb['port'], lb['state'],
                 cs_name, cs_ip, cs_port, cs_state,
                 gslb_name, gslb_domain]
                + [enrich[c] for c in ENRICH_COLS]
                + [owner_source])

        backends = lb['backends']
        if not backends:
            # Keep the VIP visible even with nothing behind it (likely dead)
            stats['lb_no_backends'] += 1
            out_rows.append(['(no backends)', '', '', '', ''] + base)
        else:
            for b in backends:
                out_rows.append(
                    [b['name'], b['ip'], b['fqdn'], b['status'], b['location']]
                    + base
                )
                stats['backend_rows'] += 1
                if b['ip']:
                    stats['unique_backend_ips'].add(b['ip'])

        if cs_rows:
            stats['with_cs'] += 1
        if gslb_rows:
            stats['with_gslb'] += 1
        if enrich['Owner Group']:
            stats['with_owner'] += 1
        if enrich['Application']:
            stats['with_app'] += 1

    return out_rows, stats


def main():
    # --- Resolve input/output paths ---
    args = sys.argv[1:]
    master_path = None
    if args:
        master_path = args[0]
    else:
        for cand in DEFAULT_MASTER_CANDIDATES:
            if os.path.exists(cand):
                master_path = cand
                break
    if not master_path or not os.path.exists(master_path):
        print("[ERROR] Master workbook not found. Pass its path as the first "
              "argument, e.g.:")
        print('    python backend_server_inventory.py "LB VIP Inventory_Master.xlsx"')
        sys.exit(1)

    if len(args) >= 2:
        output_file = args[1]
    else:
        os.makedirs(REPORTS_DIR, exist_ok=True)
        output_file = os.path.join(REPORTS_DIR, "backend_server_inventory.csv")

    print("=" * 80)
    print("BACKEND SERVER INVENTORY — Backend > LB VIP > CS > GSLB > Owner")
    print("=" * 80)
    print(f"  Master : {master_path}")
    print(f"  Output : {output_file}")

    # --- Load master ---
    wb, tmp_copy = open_master_workbook(master_path)
    try:
        if MASTER_SHEET_NAME in wb.sheetnames:
            ws = wb[MASTER_SHEET_NAME]
        else:
            ws = wb[wb.sheetnames[0]]
            print(f"[WARN] Sheet '{MASTER_SHEET_NAME}' not found; "
                  f"using first sheet '{ws.title}'.")

        header_row, col_map = find_header_row(ws)
        backend_blocks = find_backend_blocks(col_map)
        print(f"  Header row: {header_row} | Columns: {len(col_map)} | "
              f"Backend blocks: {len(backend_blocks)}")

        rows = load_master_rows(ws, header_row, col_map, backend_blocks)
    finally:
        wb.close()
        if tmp_copy and os.path.exists(tmp_copy):
            os.remove(tmp_copy)

    by_type = defaultdict(int)
    for r in rows:
        by_type[r['type'] or '(blank)'] += 1
    print(f"  Master rows: {len(rows)} → " +
          ", ".join(f"{t}: {n}" for t, n in sorted(by_type.items())))

    # --- Transform ---
    out_rows, stats = build_backend_inventory(rows)

    # --- Write CSV ---
    with open(output_file, 'w', newline='', encoding='utf-8-sig') as f:
        writer = csv.writer(f)
        writer.writerow(OUTPUT_HEADER)
        writer.writerows(out_rows)

    # --- Summary ---
    print()
    print(f"[DONE] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  LB vservers processed : {stats['lb_vservers']:,}")
    print(f"    with CS in front    : {stats['with_cs']:,}")
    print(f"    with GSLB in front  : {stats['with_gslb']:,}")
    print(f"    owner resolved      : {stats['with_owner']:,}")
    print(f"    application resolved: {stats['with_app']:,}")
    print(f"    no backends (likely dead): {stats['lb_no_backends']:,}")
    print(f"  Backend server rows   : {stats['backend_rows']:,} "
          f"({len(stats['unique_backend_ips']):,} unique backend IPs)")
    print(f"  Output rows           : {len(out_rows):,}")
    print(f"  CSV: {output_file}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[INFO] Interrupted by user")
    except Exception as e:
        print(f"\n[ERROR] {e}")
        import traceback
        traceback.print_exc()
