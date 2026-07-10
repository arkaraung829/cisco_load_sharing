#!/usr/bin/env python3
"""
citrix_merge_diagnose.py  —  READ-ONLY diagnostic for the master merge.

Answers: "why are Contact / Status (and other owner columns) blank in the
merged output when Master.csv has them?"

It compares Main (combined_load_balancers) against Master.csv WITHOUT writing
anything, and reports:
  1. Which owner columns actually exist in each file.
  2. How VPX values compare between the two files (the usual culprit after
     switching the join to VPX + Virtual Server Name).
  3. Match rates under three key strategies:
        exact  VPX + Virtual Server Name   (what the merge uses now)
        norm   VPX + Name, whitespace/case-normalized
        name   Virtual Server Name only    (the old behavior)
  4. Of Master rows that HAVE owner data, how many actually reach a Main row
     under each strategy.
  5. Concrete examples of Master rows that have Contact/Status but fail the
     exact VPX+Name match — showing the VPX on each side so you can see the
     mismatch.

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

KEY = ['VPX', 'Virtual Server Name']
OWNER_COLS = [
    'Owner Group', 'Contact', 'Status', 'Change Date', 'Change Record',
    'PPS Family', 'Support', 'Tech Lead', 'PM', 'PPS Lead', 'VP', 'Application',
    'Redundancy',
]
# Columns whose blanks in the screenshot prompted this check
FOCUS_COLS = ['Contact', 'Status']


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


def norm_series(s):
    return s.str.strip().str.upper()


def hr(title):
    print("\n" + "=" * 78)
    print(title)
    print("=" * 78)


def main():
    main_path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_MAIN
    master_path = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_MASTER

    hr("LOADING")
    main_df = load(main_path, "Main   ")
    ref_df = load(master_path, "Master ")

    # ---- 1. Columns present ----
    hr("1. OWNER COLUMNS PRESENT")
    for c in OWNER_COLS:
        in_main = "yes" if c in main_df.columns else "NO"
        in_ref = "yes" if c in ref_df.columns else "NO"
        nonblank_ref = (ref_df[c].astype(str).str.strip() != '').sum() if c in ref_df.columns else 0
        print(f"  {c:<16} Main:{in_main:<4} Master:{in_ref:<4} "
              f"Master non-blank: {nonblank_ref:,}")

    for key in KEY:
        if key not in main_df.columns:
            print(f"\n[ERROR] Main is missing join column '{key}' — cannot match.")
            return
        if key not in ref_df.columns:
            print(f"\n[ERROR] Master is missing join column '{key}' — cannot match.")
            return

    # ---- 2. VPX comparison ----
    hr("2. VPX VALUES — Main vs Master")
    main_vpx = set(main_df['VPX'].unique())
    ref_vpx = set(ref_df['VPX'].unique())
    print(f"  Distinct VPX in Main   : {len(main_vpx)}")
    print(f"  Distinct VPX in Master : {len(ref_vpx)}")
    common = sorted(main_vpx & ref_vpx)
    only_main = sorted(main_vpx - ref_vpx)
    only_ref = sorted(ref_vpx - main_vpx)
    print(f"  Exactly matching VPX values : {len(common)}")
    if common:
        print("    e.g. " + ", ".join(repr(v) for v in common[:5]))
    print(f"  VPX only in Main   : {len(only_main)}")
    for v in only_main[:10]:
        print(f"      {v!r}")
    print(f"  VPX only in Master : {len(only_ref)}")
    for v in only_ref[:10]:
        print(f"      {v!r}")
    # Normalized VPX overlap (catches case/space diffs)
    norm_main_vpx = set(norm_series(main_df['VPX']).unique())
    norm_ref_vpx = set(norm_series(ref_df['VPX']).unique())
    print(f"  After strip+UPPER, matching VPX values : {len(norm_main_vpx & norm_ref_vpx)}")

    # ---- 3. Match rates under each strategy ----
    hr("3. MATCH RATE — how many Main rows find a Master row")
    total_main = len(main_df)

    main_key_exact = list(zip(main_df['VPX'], main_df['Virtual Server Name']))
    ref_key_exact = set(zip(ref_df['VPX'], ref_df['Virtual Server Name']))
    exact_hits = sum(1 for k in main_key_exact if k in ref_key_exact)

    main_key_norm = list(zip(norm_series(main_df['VPX']), norm_series(main_df['Virtual Server Name'])))
    ref_key_norm = set(zip(norm_series(ref_df['VPX']), norm_series(ref_df['Virtual Server Name'])))
    norm_hits = sum(1 for k in main_key_norm if k in ref_key_norm)

    ref_names = set(ref_df['Virtual Server Name'])
    name_hits = main_df['Virtual Server Name'].isin(ref_names).sum()

    # Is the vserver name actually unique within Master? (decides if name-only is safe)
    name_counts = ref_df['Virtual Server Name'].value_counts()
    dup_names = (name_counts > 1).sum()

    def pct(n):
        return f"{n:,} ({n / total_main * 100:.1f}%)" if total_main else "0"

    print(f"  Main rows                          : {total_main:,}")
    print(f"  Matched on exact VPX + Name (now)  : {pct(exact_hits)}")
    print(f"  Matched on strip+UPPER VPX + Name  : {pct(norm_hits)}")
    print(f"  Matched on Virtual Server Name only: {pct(name_hits)}")
    print(f"  Vserver names duplicated in Master : {dup_names} "
          f"(if 0, name-only matching is unambiguous)")

    # ---- 4. Reachability of Master owner data ----
    hr("4. MASTER ROWS THAT HAVE OWNER DATA — do they reach Main?")
    have_owner = ref_df[[c for c in OWNER_COLS if c in ref_df.columns]].apply(
        lambda r: any(str(x).strip() for x in r), axis=1)
    ref_with = ref_df[have_owner]
    print(f"  Master rows with any owner value   : {len(ref_with):,}")
    rexact = set(zip(main_df['VPX'], main_df['Virtual Server Name']))
    reach_exact = ref_with.apply(
        lambda r: (r['VPX'], r['Virtual Server Name']) in rexact, axis=1).sum()
    rnorm = set(zip(norm_series(main_df['VPX']), norm_series(main_df['Virtual Server Name'])))
    reach_norm = ref_with.apply(
        lambda r: (str(r['VPX']).strip().upper(),
                   str(r['Virtual Server Name']).strip().upper()) in rnorm, axis=1).sum()
    main_names = set(main_df['Virtual Server Name'])
    reach_name = ref_with['Virtual Server Name'].isin(main_names).sum()
    print(f"    reach Main via exact VPX+Name    : {reach_exact:,}")
    print(f"    reach Main via norm  VPX+Name    : {reach_norm:,}")
    print(f"    reach Main via Name only         : {reach_name:,}")
    gained = reach_name - reach_exact
    if gained > 0:
        print(f"  >> {gained:,} owner rows are LOST by exact VPX+Name that "
              f"name-only would have matched.")

    # ---- 5. Concrete failing examples ----
    hr("5. EXAMPLES — Master rows WITH Contact/Status that FAIL exact VPX+Name")
    focus = [c for c in FOCUS_COLS if c in ref_df.columns]
    if not focus:
        print("  (Neither Contact nor Status exists as a column in Master.csv — "
              "that alone would explain blanks. Check the exact header text.)")
    else:
        has_focus = ref_df[focus].apply(
            lambda r: any(str(x).strip() for x in r), axis=1)
        cand = ref_df[has_focus].copy()
        cand['_exact'] = cand.apply(
            lambda r: (r['VPX'], r['Virtual Server Name']) in rexact, axis=1)
        failing = cand[~cand['_exact']]
        print(f"  Master rows with {focus} filled : {len(cand):,}")
        print(f"  ...of those, FAIL exact VPX+Name : {len(failing):,}")
        # For a few, show whether the NAME exists in Main and under which VPX
        main_by_name = main_df.groupby('Virtual Server Name')['VPX'].apply(
            lambda s: sorted(set(s))).to_dict()
        shown = 0
        for _, r in failing.iterrows():
            if shown >= 15:
                print(f"  ... and {len(failing) - 15} more")
                break
            name = r['Virtual Server Name']
            main_vpxs = main_by_name.get(name)
            if main_vpxs is None:
                where = "name NOT in Main at all"
            else:
                where = f"Main has this name under VPX {main_vpxs}"
            contact = (r.get('Contact', '') or '')[:22]
            print(f"    Master VPX={r['VPX']!r} Name={name!r} Contact={contact!r}")
            print(f"        -> {where}")
            shown += 1
        if len(failing) == 0:
            print("  None — exact VPX+Name matches every owner-bearing row. "
                  "Blanks you see are likely genuinely-empty Master cells or "
                  "truly Main-only vservers.")

    hr("DONE — read-only, nothing was written")


if __name__ == "__main__":
    main()
