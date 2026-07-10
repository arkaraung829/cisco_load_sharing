#!/usr/bin/env python3
"""
citrix_merge_diagnose.py  —  READ-ONLY diagnostic for the master merge.

Answers: "why are Owner Group / Contact / Status blank in the merged output
when Master.csv has them?"

It compares Main (combined_load_balancers) against Master.csv WITHOUT writing
anything, applying the SAME HA-pair VPX normalization the merge uses, and
classifies every Main row's enrichment outcome so you can see exactly where
matching breaks (VPX vs Virtual Server Name vs genuinely-empty Master cell).

Usage:
    python citrix_merge_diagnose.py [main.csv] [master.csv]

Defaults match citrix_merge_from_master.py.
"""

import os
import sys
import subprocess
import importlib


def install_if_missing(packages):
    for pkg in packages:
        try:
            importlib.import_module(pkg)
        except ImportError:
            subprocess.run([sys.executable, "-m", "pip", "install", pkg],
                           capture_output=True, text=True)


install_if_missing(["pandas", "chardet"])
import pandas as pd
try:
    import chardet
except ImportError:
    chardet = None


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, "..", ".."))
REPORTS_DIR = os.path.join(PROJECT_ROOT, "reports", "citrix")

DEFAULT_MAIN = os.path.join(REPORTS_DIR, "combined_load_balancers 1.csv")
DEFAULT_MASTER = os.path.join(SCRIPT_DIR, "Master.csv")

OWNER_COLS = [
    'Owner Group', 'Contact', 'Status', 'Change Date', 'Change Record',
    'PPS Family', 'Support', 'Tech Lead', 'PM', 'PPS Lead', 'VP', 'Application',
    'Redundancy',
]
FOCUS_COLS = ['Owner Group', 'Contact', 'Status']  # what you're seeing blank

# ---- Reuse the merge's HA-pair logic so this mirrors the real merge ----
try:
    _spec = importlib.util.spec_from_file_location(
        "citrix_merge_from_master",
        os.path.join(SCRIPT_DIR, "citrix_merge_from_master.py"))
    _merge = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_merge)
    canonical_vpx = _merge.canonical_vpx
    NORMALIZE_VPX_HA_PAIRS = _merge.NORMALIZE_VPX_HA_PAIRS
    print("[INFO] Using HA-pair logic imported from citrix_merge_from_master.py")
except Exception as e:  # standalone fallback (kept in sync with the merge)
    print(f"[WARN] Could not import merge module ({e}); using built-in pairing")
    import re
    NORMALIZE_VPX_HA_PAIRS = True
    _VPX_CVL_RE = re.compile(r'(?i)^(?P<prefix>.*?CVL)(?P<n1>\d+)(?:\s*/\s*\d+)?(?P<rest>.*)$')

    def canonical_vpx(value):
        if not value:
            return value
        m = _VPX_CVL_RE.match(value.strip())
        if not m:
            return value
        n1 = m.group('n1'); num = int(n1)
        base = num if num % 2 == 1 else num - 1
        width = max(2, len(n1))
        return f"{m.group('prefix')}{base:0{width}d}/{base + 1:0{width}d}{m.group('rest') or ''}"


def detect_encoding(path):
    if chardet:
        with open(path, 'rb') as f:
            raw = f.read(100_000)
        enc = chardet.detect(raw).get('encoding') or 'utf-8'
        if enc.lower() in ('ascii', 'windows-1254'):
            enc = 'cp1252'
        return enc
    for enc in ['utf-8-sig', 'utf-8', 'cp1252', 'latin-1']:
        try:
            with open(path, 'r', encoding=enc) as f:
                f.read(10_000)
            return enc
        except (UnicodeDecodeError, UnicodeError):
            continue
    return 'latin-1'


def load(path, label):
    if not os.path.exists(path):
        print(f"[ERROR] {label} not found: {path}")
        sys.exit(1)
    enc = detect_encoding(path)
    df = pd.read_csv(path, encoding=enc, dtype=str, keep_default_na=False,
                     on_bad_lines='warn')
    df.columns = df.columns.str.strip()
    for c in df.columns:
        df[c] = df[c].str.strip()
    print(f"  {label}: {len(df):,} rows x {len(df.columns)} cols  (encoding {enc})")
    return df


def hr(title):
    print("\n" + "=" * 78)
    print(title)
    print("=" * 78)


def pair(v):
    return canonical_vpx(v) if NORMALIZE_VPX_HA_PAIRS else v


def main():
    main_path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_MAIN
    master_path = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_MASTER

    hr("LOADING")
    main_df = load(main_path, "Main   ")
    ref_df = load(master_path, "Master ")

    for key in ['VPX', 'Virtual Server Name']:
        if key not in main_df.columns:
            print(f"[ERROR] Main is missing '{key}'"); return
        if key not in ref_df.columns:
            print(f"[ERROR] Master is missing '{key}'"); return

    # ---- 1. Owner columns present? ----
    hr("1. OWNER COLUMNS — present, and non-blank count in Master")
    for c in OWNER_COLS:
        in_main = "yes" if c in main_df.columns else "NO"
        in_ref = "yes" if c in ref_df.columns else "NO"
        nonblank = (ref_df[c].str.strip() != '').sum() if c in ref_df.columns else 0
        print(f"  {c:<16} Main:{in_main:<4} Master:{in_ref:<4} Master non-blank: {nonblank:,}")
    missing_in_ref = [c for c in FOCUS_COLS if c not in ref_df.columns]
    if missing_in_ref:
        print(f"\n  [!] Master.csv has NO column named {missing_in_ref} — exact header "
              f"text must match. That alone would explain the blanks.")

    # ---- 2. VPX after HA pairing ----
    hr("2. VPX AFTER HA PAIRING — Main vs Master")
    main_vpx_p = main_df['VPX'].map(pair)
    ref_vpx_p = ref_df['VPX'].map(pair)
    mset, rset = set(main_vpx_p.unique()), set(ref_vpx_p.unique())
    print(f"  Distinct paired VPX in Main   ({len(mset)}): {sorted(mset)[:8]}")
    print(f"  Distinct paired VPX in Master ({len(rset)}): {sorted(rset)[:8]}")
    print(f"  Paired VPX present in BOTH    : {len(mset & rset)}")
    only_m = sorted(mset - rset); only_r = sorted(rset - mset)
    if only_m:
        print(f"  Paired VPX only in Main   : {only_m[:10]}")
    if only_r:
        print(f"  Paired VPX only in Master : {only_r[:10]}")

    # ---- 3. Match rate under paired VPX + Name ----
    hr("3. MATCH RATE (paired VPX + Virtual Server Name)")
    main_key = list(zip(main_vpx_p, main_df['Virtual Server Name']))
    ref_key = set(zip(ref_vpx_p, ref_df['Virtual Server Name']))
    hits = sum(1 for k in main_key if k in ref_key)
    tot = len(main_df)
    print(f"  Main rows                : {tot:,}")
    print(f"  Match on paired VPX+Name : {hits:,} ({hits / tot * 100:.1f}%)" if tot else "  (empty)")
    # name-only, to see if VPX is the blocker
    ref_names = set(ref_df['Virtual Server Name'])
    name_hits = main_df['Virtual Server Name'].isin(ref_names).sum()
    print(f"  Match on Name only       : {name_hits:,} ({name_hits / tot * 100:.1f}%)" if tot else "")
    if name_hits > hits:
        print(f"  >> {name_hits - hits:,} rows match by NAME but not by paired VPX "
              f"-> VPX still differs for these (check section 2 / add VPX_PAIR_OVERRIDES).")

    # ---- 4. WHY each Main row is (not) enriched ----
    hr("4. WHY MAIN ROWS ARE BLANK — classification of every Main row")
    focus = [c for c in FOCUS_COLS if c in ref_df.columns]
    # Master lookup: (pairedVPX, name) -> does it have any focus value?
    ref_lookup = {}
    for _, r in ref_df.iterrows():
        k = (pair(r['VPX']), r['Virtual Server Name'])
        has_val = any(str(r.get(c, '')).strip() for c in focus) if focus else False
        # keep True if any dup has a value
        ref_lookup[k] = ref_lookup.get(k, False) or has_val
    name_to_pairedvpx = {}
    for _, r in ref_df.iterrows():
        name_to_pairedvpx.setdefault(r['Virtual Server Name'], set()).add(pair(r['VPX']))

    cnt = {"matched_with_data": 0, "matched_master_blank": 0,
           "name_diff_vpx": 0, "name_absent": 0}
    examples = {"matched_master_blank": [], "name_diff_vpx": [], "name_absent": []}
    for i in range(len(main_df)):
        pvpx = main_key[i][0]
        name = main_df.iloc[i]['Virtual Server Name']
        k = (pvpx, name)
        if k in ref_lookup:
            if ref_lookup[k]:
                cnt["matched_with_data"] += 1
            else:
                cnt["matched_master_blank"] += 1
                if len(examples["matched_master_blank"]) < 8:
                    examples["matched_master_blank"].append((pvpx, name))
        elif name in name_to_pairedvpx:
            cnt["name_diff_vpx"] += 1
            if len(examples["name_diff_vpx"]) < 8:
                examples["name_diff_vpx"].append(
                    (pvpx, name, sorted(name_to_pairedvpx[name])))
        else:
            cnt["name_absent"] += 1
            if len(examples["name_absent"]) < 8:
                examples["name_absent"].append((pvpx, name))

    print(f"  MATCHED, Master has data   : {cnt['matched_with_data']:,}   "
          f"(these SHOULD be enriched)")
    print(f"  MATCHED, Master cell blank : {cnt['matched_master_blank']:,}   "
          f"(blank because Master itself is empty)")
    print(f"  NAME in Master, VPX differs: {cnt['name_diff_vpx']:,}   "
          f"(VPX pairing still off — fixable)")
    print(f"  NAME not in Master at all  : {cnt['name_absent']:,}   "
          f"(genuinely Main-only; blank is correct)")

    if examples["name_diff_vpx"]:
        print("\n  --- Examples: name matches but VPX differs (THE fixable ones) ---")
        for pvpx, name, rvpxs in examples["name_diff_vpx"]:
            print(f"    Main pairedVPX={pvpx!r}  Name={name!r}")
            print(f"        Master has this name under pairedVPX {rvpxs}")
    if examples["name_absent"]:
        print("\n  --- Examples: name not found in Master (blank is expected) ---")
        for pvpx, name in examples["name_absent"]:
            print(f"    Main pairedVPX={pvpx!r}  Name={name!r}")
    if examples["matched_master_blank"]:
        print("\n  --- Examples: matched, but Master's own cell is empty ---")
        for pvpx, name in examples["matched_master_blank"]:
            print(f"    pairedVPX={pvpx!r}  Name={name!r}")

    hr("SUMMARY")
    if cnt["matched_with_data"] == 0:
        print("  0 rows matched with Master data. If section 3 shows Name-only")
        print("  matches > paired matches, the VPX labels still differ — compare the")
        print("  two VPX lists in section 2. If Name-only is ALSO ~0, the Virtual")
        print("  Server Name text differs between the files (suffixes/case), or you")
        print("  are viewing the raw extractor file instead of *_MERGED.csv.")
    else:
        print(f"  {cnt['matched_with_data']:,} Main rows should show Master data after a")
        print("  fresh merge. If your open file doesn't, re-run citrix_merge_from_master.py")
        print("  and open combined_load_balancers_MERGED.csv (VPX will read '.../CVLxx/yy').")
    print("\n  (read-only — nothing was written)")


if __name__ == "__main__":
    main()
