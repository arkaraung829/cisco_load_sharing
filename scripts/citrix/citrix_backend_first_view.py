"""
citrix_backend_first_view.py

Rearranges the Citrix extractor's output WITHOUT touching the extractor.

citrix_vip_backend_extractor.py writes combined_load_balancers.csv as one
WIDE row per vserver:

    ... vserver columns ... | Backend1 block | Backend2 block | ... BackendN

This script reads that CSV after the data is gathered and flips the layout:

    ONE ROW PER BACKEND SERVER — backend columns FIRST, vserver beside it:

    Backend Name | Backend IP | FQDN | Status | Location | VPX | Type |
    Virtual Server Name | Virtual Server IP | ... | GSLB Domain | Policy ...

Rules:
    - Every BackendName{i}/BackendIP{i}/BackendHost_FQDN{i}/BackendStatus{i}/
      BackendLocation{i} group with data becomes its own output row.
    - All non-backend columns (Owner Group ... Application, VPX, vserver
      details, GSLB Domain, policy columns) are carried over unchanged, so
      nothing from the wide file is lost — including owner/app enrichment
      if you run it against the MERGED file.
    - Vservers with NO backends (CS/CR/VPN rows, empty LBs) are kept as a
      single row with blank backend columns so the inventory stays complete.

Usage:
    python citrix_backend_first_view.py [input.csv] [output.csv]

Defaults:
    input  : <project>/reports/citrix/combined_load_balancers.csv
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

DEFAULT_INPUT_CANDIDATES = [
    os.path.join(REPORTS_DIR, "combined_load_balancers.csv"),
    os.path.join(REPORTS_DIR, "combined_load_balancers_MERGED.csv"),
]

BACKEND_FIELDS = ['BackendName', 'BackendIP', 'BackendHost_FQDN',
                  'BackendStatus', 'BackendLocation']
BACKEND_OUT_HEADER = ['Backend Name', 'Backend IP', 'Backend Host FQDN',
                      'Backend Status', 'Backend Location']


def find_backend_columns(header):
    """
    Detect BackendName1..N (and their IP/FQDN/Status/Location partners) by
    header name, so any max-backend width the extractor produced works.
    Returns (blocks, backend_col_idxs):
        blocks: list of [name_idx, ip_idx, fqdn_idx, status_idx, loc_idx]
                sorted by backend number (missing partner -> None)
        backend_col_idxs: set of all column indexes that belong to backends
    """
    pos = {name: idx for idx, name in enumerate(header)}
    numbers = set()
    backend_idxs = set()
    pat = re.compile(r'^(' + '|'.join(BACKEND_FIELDS) + r')(\d+)$')
    for name, idx in pos.items():
        m = pat.match(name)
        if m:
            numbers.add(int(m.group(2)))
            backend_idxs.add(idx)

    blocks = []
    for i in sorted(numbers):
        blocks.append([pos.get(f'{field}{i}') for field in BACKEND_FIELDS])
    return blocks, backend_idxs


def get(row, idx):
    if idx is None or idx >= len(row):
        return ''
    return row[idx].strip()


def rearrange(input_file, output_file):
    with open(input_file, mode='r', newline='', encoding='utf-8-sig') as f:
        reader = csv.reader(f)
        header = next(reader)

        blocks, backend_idxs = find_backend_columns(header)
        if not blocks:
            print("[ERROR] No BackendName1.. columns found in the input header. "
                  "Is this the extractor's combined_load_balancers.csv?")
            sys.exit(1)

        # Every non-backend column is carried over, in original order
        keep_idxs = [i for i in range(len(header)) if i not in backend_idxs]
        out_header = BACKEND_OUT_HEADER + [header[i] for i in keep_idxs]

        print(f"  Input columns : {len(header)} "
              f"({len(blocks)} backend blocks, {len(keep_idxs)} vserver/owner columns)")

        vservers = 0
        vservers_no_backends = 0
        backend_rows = 0
        unique_backend_ips = set()
        rows_by_type = defaultdict(int)

        with open(output_file, mode='w', newline='', encoding='utf-8') as out:
            writer = csv.writer(out)
            writer.writerow(out_header)

            type_idx = None
            if 'Type of Virtual Server' in header:
                type_idx = header.index('Type of Virtual Server')

            for row in reader:
                if not any(c.strip() for c in row):
                    continue
                vservers += 1
                vserver_cols = [get(row, i) for i in keep_idxs]
                if type_idx is not None:
                    rows_by_type[get(row, type_idx) or '(blank)'] += 1

                wrote_backend = False
                for name_i, ip_i, fqdn_i, status_i, loc_i in blocks:
                    bname = get(row, name_i)
                    bip = get(row, ip_i)
                    if not bname and not bip:
                        continue
                    writer.writerow([bname, bip, get(row, fqdn_i),
                                     get(row, status_i), get(row, loc_i)]
                                    + vserver_cols)
                    backend_rows += 1
                    wrote_backend = True
                    if bip and bip not in ('N/A', '0.0.0.0'):
                        unique_backend_ips.add(bip)

                if not wrote_backend:
                    # Keep vservers with nothing behind them visible
                    writer.writerow(['', '', '', '', ''] + vserver_cols)
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
        print("[ERROR] Input CSV not found. Pass the extractor output as the "
              "first argument, e.g.:")
        print("    python citrix_backend_first_view.py combined_load_balancers.csv")
        sys.exit(1)

    if len(args) >= 2:
        output_file = args[1]
    else:
        base, ext = os.path.splitext(input_file)
        output_file = f"{base}_backend_first{ext or '.csv'}"

    print("=" * 80)
    print("CITRIX BACKEND-FIRST VIEW — one row per backend, vserver beside it")
    print("=" * 80)
    print(f"  Input  : {input_file}")
    print(f"  Output : {output_file}")

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
