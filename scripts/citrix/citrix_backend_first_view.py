"""
citrix_backend_first_view.py

Builds the APP-TEAM view from the Citrix extractor/merge output WITHOUT
touching the extractor.

Input is the wide CSV (one row per vserver, Backend1..N column blocks) —
preferably combined_load_balancers_MERGED.csv so owner/app enrichment is
present. Output is ONE ROW PER BACKEND SERVER in the fixed app-team layout:

    Owner Group | Application | Backend Name (Configured in Load Balancer) |
    Backend IP | Backend Host FQDN (From Reverse DNS Lookup) |
    Backend Status/Affected Status | Backend Location | Status | Change Date |
    Change Record | Contact | PPS Family | Support | Tech Lead | PM |
    PPS Lead | VP | Environment | VPX | Type of Virtual Server |
    Virtual Server Name | Virtual Server IP | Virtual Server Port |
    VIP Status | Final VIP Status | Redundancy | Progress Summary |
    GSLB Domain | Policy Rule | Target LB VServer | Policy Action |
    Target VServer | Target LB Status

Rules:
    - Every BackendName{i}/BackendIP{i}/... group with data becomes its own row.
    - Vservers with NO backends (CS/CR/VPN rows, empty LBs) are kept as a
      single row with blank backend columns so the inventory stays complete.
    - Input columns missing from the source file (e.g. 'Environment' when run
      against a raw extract, or 'Final VIP Status' which the app team fills
      in manually) are emitted blank and reported once at startup.

Usage:
    python citrix_backend_first_view.py [input.csv] [output.csv]

Defaults:
    input  : <project>/reports/citrix/combined_load_balancers_MERGED.csv
             (falls back to combined_load_balancers.csv — owners blank there)
    output : <input basename>_backend_first.csv, same folder
"""

import sys
import os
import re
import csv
from datetime import datetime
from collections import defaultdict

# ===== PATH SETUP =====
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, "..", ".."))
REPORTS_DIR = os.path.join(PROJECT_ROOT, "reports", "citrix")

# Prefer the MERGED file: it carries Owner Group / Application / Environment.
DEFAULT_INPUT_CANDIDATES = [
    os.path.join(REPORTS_DIR, "combined_load_balancers_MERGED.csv"),
    os.path.join(REPORTS_DIR, "combined_load_balancers.csv"),
]

BACKEND_FIELDS = ['BackendName', 'BackendIP', 'BackendHost_FQDN',
                  'BackendStatus', 'BackendLocation']

# ===== APP-TEAM OUTPUT LAYOUT (fixed column order) =====
# Each entry: (output header, source). source is either
#   ('backend', i)  -> field i of the backend block (0=name .. 4=location)
#   ('col', name)   -> carried from the input column of that name ('' if absent)
APP_TEAM_LAYOUT = [
    ('Owner Group',                                   ('col', 'Owner Group')),
    ('Application',                                   ('col', 'Application')),
    ('Backend Name (Configured in Load Balancer)',    ('backend', 0)),
    ('Backend IP',                                    ('backend', 1)),
    ('Backend Host FQDN (From Reverse DNS Lookup)',   ('backend', 2)),
    ('Backend Status/Affected Status',                ('backend', 3)),
    ('Backend Location',                              ('backend', 4)),
    ('Status',                                        ('col', 'Status')),
    ('Change Date',                                   ('col', 'Change Date')),
    ('Change Record',                                 ('col', 'Change Record')),
    ('Contact',                                       ('col', 'Contact')),
    ('PPS Family',                                    ('col', 'PPS Family')),
    ('Support',                                       ('col', 'Support')),
    ('Tech Lead',                                     ('col', 'Tech Lead')),
    ('PM',                                            ('col', 'PM')),
    ('PPS Lead',                                      ('col', 'PPS Lead')),
    ('VP',                                            ('col', 'VP')),
    ('Environment',                                   ('col', 'Environment')),
    ('VPX',                                           ('col', 'VPX')),
    ('Type of Virtual Server',                        ('col', 'Type of Virtual Server')),
    ('Virtual Server Name',                           ('col', 'Virtual Server Name')),
    ('Virtual Server IP',                             ('col', 'Virtual Server IP')),
    ('Virtual Server Port',                           ('col', 'Virtual Server Port')),
    ('VIP Status',                                    ('col', 'VIP Status')),
    ('Final VIP Status',                              ('col', 'Final VIP Status')),
    ('Redundancy',                                    ('col', 'Redundancy')),
    ('Progress Summary',                              ('col', 'Progress Summary')),
    ('GSLB Domain',                                   ('col', 'GSLB Domain')),
    ('Policy Rule',                                   ('col', 'Policy Rule')),
    ('Target LB VServer',                             ('col', 'Target LB VServer')),
    ('Policy Action',                                 ('col', 'Policy Action')),
    ('Target VServer',                                ('col', 'Target VServer')),
    ('Target LB Status',                              ('col', 'Target LB Status')),
]


def detect_input_encoding(path):
    """
    The extractor writes utf-8; the merge writes utf-8-sig; Excel re-saves as
    cp1252. Try in that order — utf-8-sig also reads plain utf-8/ascii, and
    latin-1 is a last resort that never fails.
    """
    for enc in ('utf-8-sig', 'cp1252'):
        try:
            with open(path, mode='r', newline='', encoding=enc) as f:
                for _ in f:
                    pass
            return enc
        except UnicodeDecodeError:
            continue
    return 'latin-1'


def find_backend_columns(header):
    """
    Detect BackendName1..N (and their IP/FQDN/Status/Location partners) by
    header name, so any max-backend width the extractor produced works.
    Returns: blocks — list of [name_idx, ip_idx, fqdn_idx, status_idx, loc_idx]
    sorted by backend number (missing partner -> None).
    """
    pos = {name: idx for idx, name in enumerate(header)}
    numbers = set()
    pat = re.compile(r'^(' + '|'.join(BACKEND_FIELDS) + r')(\d+)$')
    for name in pos:
        m = pat.match(name)
        if m:
            numbers.add(int(m.group(2)))

    blocks = []
    for i in sorted(numbers):
        blocks.append([pos.get(f'{field}{i}') for field in BACKEND_FIELDS])
    return blocks


def get(row, idx):
    if idx is None or idx >= len(row):
        return ''
    return row[idx].strip()


def rearrange(input_file, output_file):
    encoding = detect_input_encoding(input_file)
    print(f"  Encoding: {encoding}")

    with open(input_file, mode='r', newline='', encoding=encoding) as f:
        reader = csv.reader(f)
        header = [h.strip() for h in next(reader)]

        blocks = find_backend_columns(header)
        if not blocks:
            print("[ERROR] No BackendName1.. columns found in the input header. "
                  "Is this the extractor's combined_load_balancers CSV?")
            sys.exit(1)

        pos = {name: idx for idx, name in enumerate(header)}
        # Resolve each layout entry to a column index now; None -> blank
        col_sources = []
        missing_cols = []
        for out_name, source in APP_TEAM_LAYOUT:
            if source[0] == 'col':
                idx = pos.get(source[1])
                if idx is None:
                    missing_cols.append(source[1])
                col_sources.append(('col', idx))
            else:
                col_sources.append(source)

        out_header = [name for name, _ in APP_TEAM_LAYOUT]

        print(f"  Input columns : {len(header)} ({len(blocks)} backend blocks)")
        if missing_cols:
            print(f"  Not in input (emitted blank): {missing_cols}")

        vservers = 0
        vservers_no_backends = 0
        backend_rows = 0
        unique_backend_ips = set()
        rows_by_type = defaultdict(int)
        type_idx = pos.get('Type of Virtual Server')

        with open(output_file, mode='w', newline='', encoding='utf-8-sig') as out:
            writer = csv.writer(out)
            writer.writerow(out_header)

            for row in reader:
                if not any(c.strip() for c in row):
                    continue
                vservers += 1
                if type_idx is not None:
                    rows_by_type[get(row, type_idx) or '(blank)'] += 1

                def emit(backend_vals):
                    out_row = []
                    for kind_idx, src in zip(col_sources, APP_TEAM_LAYOUT):
                        kind = kind_idx[0]
                        if kind == 'col':
                            out_row.append(get(row, kind_idx[1]))
                        else:  # ('backend', i)
                            out_row.append(backend_vals[src[1][1]])
                    writer.writerow(out_row)

                wrote_backend = False
                for name_i, ip_i, fqdn_i, status_i, loc_i in blocks:
                    bname = get(row, name_i)
                    bip = get(row, ip_i)
                    if not bname and not bip:
                        continue
                    emit([bname, bip, get(row, fqdn_i),
                          get(row, status_i), get(row, loc_i)])
                    backend_rows += 1
                    wrote_backend = True
                    if bip and bip not in ('N/A', '0.0.0.0'):
                        unique_backend_ips.add(bip)

                if not wrote_backend:
                    # Keep vservers with nothing behind them visible
                    emit(['', '', '', '', ''])
                    vservers_no_backends += 1

    return {
        'vservers': vservers,
        'vservers_no_backends': vservers_no_backends,
        'backend_rows': backend_rows,
        'unique_backend_ips': len(unique_backend_ips),
        'rows_by_type': dict(rows_by_type),
    }


def main():
    args = sys.argv[1:]

    input_file = None
    if args:
        input_file = args[0]
    else:
        for cand in DEFAULT_INPUT_CANDIDATES:
            if os.path.exists(cand):
                input_file = cand
                break
    if not input_file or not os.path.exists(input_file):
        print("[ERROR] Input CSV not found. Pass the merged (or extractor) "
              "output as the first argument, e.g.:")
        print("    python citrix_backend_first_view.py combined_load_balancers_MERGED.csv")
        sys.exit(1)

    if len(args) >= 2:
        output_file = args[1]
    else:
        base, ext = os.path.splitext(input_file)
        output_file = f"{base}_backend_first{ext or '.csv'}"

    print("=" * 80)
    print("CITRIX BACKEND-FIRST VIEW — app-team format, one row per backend")
    print("=" * 80)
    print(f"  Input  : {input_file}")
    print(f"  Output : {output_file}")
    if 'MERGED' not in os.path.basename(input_file).upper():
        print("  [NOTE] Input is not the MERGED file — Owner Group/Application/"
              "Environment will be blank. Run citrix_merge_from_master.py first "
              "for the enriched app-team view.")

    stats = rearrange(input_file, output_file)

    print(f"\n[DONE] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  vServers read           : {stats['vservers']:,}")
    for vtype, n in sorted(stats['rows_by_type'].items()):
        print(f"    {vtype:<24}: {n:,}")
    print(f"  Backend rows written    : {stats['backend_rows']:,}")
    print(f"  Unique backend IPs      : {stats['unique_backend_ips']:,}")
    print(f"  vServers w/o backends   : {stats['vservers_no_backends']:,} "
          f"(kept as blank-backend rows)")
    print(f"  Total output rows       : "
          f"{stats['backend_rows'] + stats['vservers_no_backends']:,}")
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
