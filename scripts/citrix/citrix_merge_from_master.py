#!/usr/bin/env python3
"""
CSV Data Merger Script - Pandas Edition
Merges data from Master.csv (reference) into combined_load_balancers.csv based on VPX + Virtual Server Name.
Optimized for handling multiple LBs with 2000+ vservers each.

FEATURES:
- Pandas-based merge for accuracy and speed
- chardet for automatic encoding detection
- Automatic backup BEFORE any processing
- Retry logic for transient errors (antivirus, OneDrive, etc.)
- File locking detection
- Validation report showing exactly what was merged/missed
"""

import os
import re
import sys
import time
import shutil
import subprocess
import importlib
from datetime import datetime

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

install_if_missing(["pandas", "chardet"])
# =====================================================

import pandas as pd
try:
    import chardet
except ImportError:
    chardet = None


# ===== PATH SETUP =====
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, "..", ".."))
REPORTS_DIR = os.path.join(PROJECT_ROOT, "reports", "citrix")
LOGS_DIR = os.path.join(PROJECT_ROOT, "logs")
os.makedirs(REPORTS_DIR, exist_ok=True)
os.makedirs(LOGS_DIR, exist_ok=True)

# ===== CONFIGURATION =====
MAIN_CSV_FILE = os.path.join(REPORTS_DIR, "combined_load_balancers 1.csv")
REFERENCE_CSV_FILE = os.path.join(SCRIPT_DIR, "Master.csv")
OUTPUT_CSV_FILE = os.path.join(REPORTS_DIR, "combined_load_balancers_MERGED.csv")

# Matching key columns (used to join main + reference)
# VPX + Virtual Server Name identifies a vserver uniquely, even when the same
# vserver name exists on more than one VPX.
MATCH_KEY_COLUMNS = ['VPX', 'Virtual Server Name']

# What to do with rows that exist in Master.csv but have NO match in Main
# (the extractor output). This matters when Main was generated for only some
# LBs, not all of them.
#   True  -> keep Master-only rows in the output so their master values
#            (owner/app) remain visible, but ONLY for VPXs present in Main
#            (so other LBs are never dragged in). Safe for single-LB runs.
#   False -> enrich matched rows only; drop Master-only rows from the output
#            (they still remain untouched in Master.csv). Output == Main rows.
APPEND_MASTER_ONLY = True

# ADCs are deployed as HA pairs (…CVL01/02, …CVL03/04, …CVL05/06). The
# extractor records whichever single node it connected to (e.g. …CVL03), but
# the Master sheet may record the pair or the other node (…CVL04). When True,
# every VPX is rewritten to its pair label (…CVL03/04) on BOTH files BEFORE
# matching, so enrichment lands regardless of which node each file recorded,
# and the merged output shows the unambiguous pair label.
NORMALIZE_VPX_HA_PAIRS = True

# Exceptions to the automatic odd/even pairing, if any node doesn't follow the
# consecutive CVL<odd>/<even> rule. Map an exact VPX value -> desired label.
#   e.g. {'LCLDMZHER-CVL07': 'LCLDMZHER-CVL07 (standalone)'}
VPX_PAIR_OVERRIDES = {}

# Matches a trailing "...CVL<num>" (optionally already "CVL<num>/<num>") so the
# node number can be paired. Case-insensitive; anything after is preserved.
_VPX_CVL_RE = re.compile(r'(?i)^(?P<prefix>.*?CVL)(?P<n1>\d+)(?:\s*/\s*\d+)?(?P<rest>.*)$')


def canonical_vpx(value):
    """
    Map an HA-pair node VPX to its pair label:
        'LCLDMZHER-CVL03'  -> 'LCLDMZHER-CVL03/04'
        'LCLDMZHER-CVL04'  -> 'LCLDMZHER-CVL03/04'
        'LCLDMZHER-CVL03/04' -> 'LCLDMZHER-CVL03/04'  (already paired)
    Pairing is consecutive odd/even (01/02, 03/04, 05/06, ...). Values with no
    'CVL<number>' token, or listed in VPX_PAIR_OVERRIDES, are returned as-is.
    """
    if not value:
        return value
    if value in VPX_PAIR_OVERRIDES:
        return VPX_PAIR_OVERRIDES[value]
    m = _VPX_CVL_RE.match(value.strip())
    if not m:
        return value
    n1 = m.group('n1')
    num = int(n1)
    base = num if num % 2 == 1 else num - 1        # odd node is the pair base
    width = max(2, len(n1))                          # preserve zero-padding
    return f"{m.group('prefix')}{base:0{width}d}/{base + 1:0{width}d}{m.group('rest') or ''}"

# Column name mapping: Master.csv name -> Main CSV name (rename before merge)
# No rename needed — both files now use the same column names
COLUMN_RENAME_MAP = {}

# Columns to update/add from reference (Master.csv)
COLUMNS_TO_UPDATE = [
    'Owner Group', 'Contact', 'Status', 'Change Date', 'Change Record',
    'PPS Family', 'Support', 'Tech Lead', 'PM', 'PPS Lead', 'VP', 'Application',
    'Redundancy',
]

# Retry config
MAX_RETRIES = 3
RETRY_DELAY = 5

# Log file
LOG_FILE = os.path.join(LOGS_DIR, f"merge_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")


# ===== LOGGING =====
_log_lines = []


def log(message, level="INFO"):
    """Log to console and buffer for file output"""
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] [{level}] {message}"
    print(line)
    _log_lines.append(line)


def save_log():
    """Write buffered log lines to file"""
    try:
        with open(LOG_FILE, 'w', encoding='utf-8') as f:
            f.write('\n'.join(_log_lines))
        print(f"\nLog saved to: {LOG_FILE}")
    except Exception as e:
        print(f"[WARNING] Could not save log file: {e}")


# ===== ENCODING DETECTION =====
def detect_encoding(filepath):
    """Detect file encoding using chardet (if available) or fallback"""
    if chardet:
        with open(filepath, 'rb') as f:
            raw = f.read(100_000)  # Read first 100KB for detection
        result = chardet.detect(raw)
        encoding = result.get('encoding', 'utf-8')
        confidence = result.get('confidence', 0)
        log(f"chardet detected: {encoding} (confidence: {confidence:.0%})")
        # Map common aliases — ASCII files with special chars are usually cp1252 (Windows)
        if encoding and encoding.lower() in ('ascii', 'windows-1254'):
            encoding = 'cp1252'
        return encoding
    else:
        # Fallback: try encodings in order
        for enc in ['utf-8-sig', 'utf-8', 'cp1252', 'latin-1']:
            try:
                with open(filepath, 'r', encoding=enc) as f:
                    f.read(10_000)
                log(f"Fallback encoding detected: {enc}")
                return enc
            except (UnicodeDecodeError, UnicodeError):
                continue
        return 'latin-1'


# ===== FILE SAFETY =====
def is_file_locked(filepath):
    """Check if file is locked by another process"""
    if not os.path.exists(filepath):
        return False, "File does not exist"
    try:
        with open(filepath, 'r+', encoding='utf-8', errors='ignore') as f:
            pass
        return False, None
    except PermissionError:
        return True, "File is locked (likely open in Excel or another program)"
    except Exception as e:
        return True, str(e)


def wait_for_file_unlock(filepath, max_retries=5, wait_seconds=5):
    """Wait for file to become accessible"""
    for attempt in range(max_retries):
        locked, error = is_file_locked(filepath)
        if not locked:
            log(f"File accessible: {os.path.basename(filepath)}", "SUCCESS")
            return True
        if attempt < max_retries - 1:
            log(f"File locked: {error}. Waiting {wait_seconds}s... (attempt {attempt + 1}/{max_retries})", "WARNING")
            log("ACTION: Close Excel, OneDrive, or any program accessing this file!", "WARNING")
            time.sleep(wait_seconds)
        else:
            log(f"File remains locked after {max_retries} attempts", "ERROR")
            return False
    return False


def create_backup(filepath):
    """Create timestamped backup"""
    if not os.path.exists(filepath):
        return None
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = f"{filepath}.backup_{timestamp}"
    try:
        shutil.copy2(filepath, backup_path)
        size_mb = os.path.getsize(backup_path) / 1024 / 1024
        log(f"Backup created: {os.path.basename(backup_path)} ({size_mb:.2f} MB)", "SUCCESS")
        return backup_path
    except Exception as e:
        log(f"Backup failed: {e}", "ERROR")
        return None


# ===== PANDAS MERGE LOGIC =====
def read_csv_safe(filepath, label="file"):
    """Read CSV with automatic encoding detection and header cleanup"""
    if not os.path.exists(filepath):
        log(f"{label} not found: {filepath}", "ERROR")
        return None

    if not wait_for_file_unlock(filepath):
        return None

    encoding = detect_encoding(filepath)
    log(f"Reading {label} with encoding: {encoding}")

    try:
        df = pd.read_csv(
            filepath,
            encoding=encoding,
            dtype=str,           # Read everything as string to prevent data loss
            keep_default_na=False,  # Don't convert blanks to NaN — keep as empty string
            on_bad_lines='warn',    # Warn about malformed rows instead of crashing
        )

        # Strip whitespace from column names (fixes " Change Date" -> "Change Date")
        df.columns = df.columns.str.strip()

        # Strip whitespace from all string values
        for col in df.columns:
            df[col] = df[col].str.strip()

        log(f"{label}: {len(df)} rows x {len(df.columns)} columns", "SUCCESS")
        return df

    except Exception as e:
        log(f"Failed to read {label}: {e}", "ERROR")
        return None


def validate_columns(df, required_cols, label="file"):
    """Check that required columns exist in DataFrame"""
    missing = [c for c in required_cols if c not in df.columns]
    if missing:
        log(f"{label} is missing required columns: {missing}", "ERROR")
        log(f"Available columns: {list(df.columns)}")
        return False
    return True


def perform_merge(main_df, ref_df):
    """
    Merge reference data into main DataFrame using Pandas.
    - OUTER join on MATCH_KEY_COLUMNS (VPX + Virtual Server Name)
    - Rows in both: update COLUMNS_TO_UPDATE from Master (preserve main if Master is blank)
    - Rows only in Main: keep as-is
    - Rows only in Master (e.g. VPX with partitions): ADD to output with all Master data
    - Deduplicate output on VPX + Virtual Server Name (keep last)
    """
    log("=" * 60)
    log("STARTING PANDAS MERGE")
    log("=" * 60)

    ref_df = ref_df.copy()
    main_df = main_df.copy()
    join_keys = MATCH_KEY_COLUMNS  # ['VPX', 'Virtual Server Name']

    # --- HA-pair VPX normalization (before any matching) ---
    # Rewrite each VPX to its pair label on BOTH files so a vserver enriches
    # regardless of which HA node the extractor vs the Master sheet recorded.
    if NORMALIZE_VPX_HA_PAIRS:
        for df, lbl in [(main_df, "Main"), (ref_df, "Master")]:
            if 'VPX' in df.columns:
                before = df['VPX'].copy()
                df['VPX'] = df['VPX'].map(canonical_vpx)
                changed = int((before != df['VPX']).sum())
                log(f"HA-pair VPX: rewrote {changed} of {len(df)} '{lbl}' VPX "
                    f"values to pair labels")
        # Show the resulting distinct VPX labels so a mismatch is obvious
        log(f"Distinct VPX after pairing — Main: {sorted(main_df['VPX'].unique())[:8]}")
        log(f"Distinct VPX after pairing — Master: {sorted(ref_df['VPX'].unique())[:8]}")

    # Rename Master.csv columns to match Main CSV names
    rename_applied = {k: v for k, v in COLUMN_RENAME_MAP.items() if k in ref_df.columns}
    if rename_applied:
        ref_df = ref_df.rename(columns=rename_applied)
        for old_name, new_name in rename_applied.items():
            log(f"Renamed Master.csv column: '{old_name}' -> '{new_name}'")

    # Check for duplicates in reference (by VPX + VS Name to preserve same VS on different VPXs)
    ref_dedup_keys = ['VPX', 'Virtual Server Name']
    ref_dupes = ref_df.duplicated(subset=ref_dedup_keys, keep='last')
    if ref_dupes.any():
        dupe_count = ref_dupes.sum()
        log(f"WARNING: {dupe_count} duplicate keys in Master.csv (keeping last occurrence)", "WARNING")
        dupe_rows = ref_df[ref_dupes].head(5)
        for _, row in dupe_rows.iterrows():
            log(f"  Duplicate: VPX='{row.get('VPX', '')}', VServer='{row.get('Virtual Server Name', '')}'", "WARNING")
        ref_df = ref_df.drop_duplicates(subset=ref_dedup_keys, keep='last')

    # Select only the columns we need from reference
    ref_cols_available = [c for c in COLUMNS_TO_UPDATE if c in ref_df.columns]
    ref_cols_missing = [c for c in COLUMNS_TO_UPDATE if c not in ref_df.columns]

    if ref_cols_missing:
        log(f"Master.csv missing these COLUMNS_TO_UPDATE: {ref_cols_missing}", "WARNING")

    log(f"Columns to merge from Master.csv: {ref_cols_available}")

    # --- Identify Master-only rows BEFORE subsetting ---
    # These are VPX+VServer combos in Master but NOT in Main (e.g. partitioned VPXs)
    main_keys = set(main_df[join_keys].apply(tuple, axis=1))
    ref_keys = set(ref_df[join_keys].apply(tuple, axis=1))
    master_only_keys = ref_keys - main_keys
    master_only_count = len(master_only_keys)

    if master_only_count > 0:
        log(f"\nMASTER-ONLY ROWS: Found {master_only_count} rows in Master.csv not in Main CSV", "WARNING")
        # Show first 10
        for i, key in enumerate(sorted(master_only_keys)):
            if i >= 10:
                log(f"  ... and {master_only_count - 10} more", "WARNING")
                break
            log(f"  NEW: VPX='{key[0]}', VServer='{key[1]}'", "WARNING")

    # Prepare reference subset for matched rows: join keys + update columns
    ref_subset = ref_df[join_keys + ref_cols_available].copy()

    # Deduplicate ref_subset on Virtual Server Name only (for merge purposes)
    # Same VS Name across VPXs should have same Owner Group/Contact/etc.
    # This prevents row multiplication during left join
    ref_subset = ref_subset.drop_duplicates(subset=join_keys, keep='last')
    log(f"Reference rows after VS Name dedup (for merge): {len(ref_subset)}")

    # Add suffix to reference columns to avoid collision during merge
    ref_rename = {col: f"{col}__ref" for col in ref_cols_available}
    ref_subset = ref_subset.rename(columns=ref_rename)

    # Left join first: keep all main rows, attach reference data where matched
    merged = main_df.merge(ref_subset, on=join_keys, how='left', indicator=True)

    # Stats
    total_main = len(merged)
    matched = (merged['_merge'] == 'both').sum()
    unmatched = (merged['_merge'] == 'left_only').sum()
    log(f"Main rows:     {total_main}")
    log(f"Matched:       {matched}")
    log(f"Unmatched:     {unmatched}")
    _append_note = "will be appended (VPX-scoped)" if APPEND_MASTER_ONLY else "ignored (append OFF)"
    log(f"Master-only:   {master_only_count} ({_append_note})")
    log(f"Match rate:    {(matched / total_main * 100) if total_main > 0 else 0:.2f}%")

    # Update columns: use reference value if non-empty, otherwise keep original
    updated_counts = {}
    for col in ref_cols_available:
        ref_col = f"{col}__ref"
        if ref_col not in merged.columns:
            continue

        # Ensure the column exists in main (add if missing)
        if col not in merged.columns:
            merged[col] = ''

        # Only overwrite where reference has a non-empty value
        mask = (merged['_merge'] == 'both') & (merged[ref_col] != '')
        count = mask.sum()
        updated_counts[col] = count

        merged.loc[mask, col] = merged.loc[mask, ref_col]

        # Drop the temporary reference column
        merged = merged.drop(columns=[ref_col])

    # Drop the merge indicator
    merged = merged.drop(columns=['_merge'])

    # --- Optionally append Master-only rows (in Master but not in Main) ---
    # Controlled by APPEND_MASTER_ONLY. When enabled, appends are restricted to
    # VPXs that are actually present in Main, so a subset run (e.g. one LB)
    # never drags in vservers from other LBs.
    if APPEND_MASTER_ONLY and master_only_count > 0:
        main_vpxs = set(main_df['VPX'].unique())
        master_only_mask = (
            ref_df[join_keys].apply(tuple, axis=1).isin(master_only_keys)
            & ref_df['VPX'].isin(main_vpxs)
        )
        master_only_rows = ref_df[master_only_mask].copy()

        skipped_other_vpx = master_only_count - len(master_only_rows)
        if skipped_other_vpx > 0:
            log(f"Skipping {skipped_other_vpx} Master-only rows on VPXs not in Main "
                f"(subset run — other LBs not dragged in)", "WARNING")

        if master_only_rows.empty:
            log("No Master-only rows to append for the VPXs present in Main", "SUCCESS")

        # Separate partition vs non-partition for logging
        partition_mask = master_only_rows['VPX'].str.contains(' - ', na=False)
        partition_count = partition_mask.sum()
        non_partition_count = (~partition_mask).sum()

        log(f"\nAPPENDING {len(master_only_rows)} Master-only rows to output:")
        log(f"  Partition VPX rows:     {partition_count}")
        log(f"  Non-partition VPX rows: {non_partition_count}")

        # Show first 10
        for _, row in master_only_rows.head(10).iterrows():
            vpx = row.get('VPX', '')
            vs = row.get('Virtual Server Name', '')
            tag = "[PARTITION]" if ' - ' in vpx else "[STANDARD]"
            log(f"  {tag} VPX='{vpx}', VServer='{vs}'")
        if len(master_only_rows) > 10:
            log(f"  ... and {len(master_only_rows) - 10} more")

        # Align columns — add any missing columns from main as empty
        for col in merged.columns:
            if col not in master_only_rows.columns:
                master_only_rows[col] = ''
        # Keep only columns that exist in merged output
        master_only_rows = master_only_rows.reindex(columns=merged.columns, fill_value='')

        merged = pd.concat([merged, master_only_rows], ignore_index=True)
        log(f"  Total rows after append: {len(merged)}", "SUCCESS")

    # Remove duplicate VServer rows (keep last occurrence)
    # Dedup on VPX + Virtual Server Name (not just VS Name) to preserve same VS on different VPXs
    dedup_keys = ['VPX', 'Virtual Server Name']
    before_dedup = len(merged)
    vserver_dupes = merged.duplicated(subset=dedup_keys, keep='last')
    if vserver_dupes.any():
        dupe_count = vserver_dupes.sum()
        log(f"\nDEDUPLICATION: Found {dupe_count} duplicate VServer rows in output", "WARNING")
        dupe_rows = merged[vserver_dupes]
        for _, row in dupe_rows.head(10).iterrows():
            log(f"  Removing: VPX='{row.get('VPX', '')}', VServer='{row.get('Virtual Server Name', '')}'", "WARNING")
        if dupe_count > 10:
            log(f"  ... and {dupe_count - 10} more", "WARNING")
        merged = merged.drop_duplicates(subset=dedup_keys, keep='last')
        log(f"  Rows before dedup: {before_dedup} -> after: {len(merged)} (removed {dupe_count})", "SUCCESS")
    else:
        log(f"\nDEDUPLICATION: No duplicate VServer rows found", "SUCCESS")

    # Log per-column update counts
    log("=" * 60)
    log("PER-COLUMN UPDATE COUNTS")
    log("=" * 60)
    for col, count in updated_counts.items():
        status = "OK" if count > 0 else "ZERO UPDATES"
        log(f"  {col:<20s}: {count:>6} rows updated  [{status}]")

    # Warn about columns with zero updates
    zero_cols = [c for c, v in updated_counts.items() if v == 0]
    if zero_cols:
        log(f"\nWARNING: These columns had ZERO updates (check Master.csv has data): {zero_cols}", "WARNING")

    log("=" * 60)
    log("MERGE COMPLETE", "SUCCESS")
    log("=" * 60)

    return merged


# ===== MAIN =====
def main():
    print("=" * 80)
    print("CSV DATA MERGER - PANDAS EDITION")
    print("Citrix Load Balancer Configuration")
    print("=" * 80)

    log(f"Configuration:")
    log(f"  Main CSV:      {MAIN_CSV_FILE}")
    log(f"  Reference CSV: {REFERENCE_CSV_FILE}")
    log(f"  Output CSV:    {OUTPUT_CSV_FILE}")

    # ---- Pre-flight checks ----
    log("\n" + "=" * 80)
    log("PRE-FLIGHT CHECKS")
    log("=" * 80)

    for label, path in [("Main CSV", MAIN_CSV_FILE), ("Reference CSV", REFERENCE_CSV_FILE)]:
        if not os.path.exists(path):
            log(f"{label} not found: {path}", "ERROR")
            return
        size_mb = os.path.getsize(path) / 1024 / 1024
        log(f"{label}: {size_mb:.2f} MB", "SUCCESS")

    # ---- Read files ----
    log("\n" + "=" * 80)
    log("LOADING DATA")
    log("=" * 80)

    main_df = read_csv_safe(MAIN_CSV_FILE, "Main CSV")
    if main_df is None:
        return

    ref_df = read_csv_safe(REFERENCE_CSV_FILE, "Reference CSV (Master.csv)")
    if ref_df is None:
        return

    # Validate required columns
    if not validate_columns(main_df, MATCH_KEY_COLUMNS, "Main CSV"):
        return
    if not validate_columns(ref_df, MATCH_KEY_COLUMNS, "Reference CSV"):
        return

    # Show column comparison
    log("\n--- Reference CSV columns ---")
    for col in COLUMNS_TO_UPDATE:
        in_ref = "YES" if col in ref_df.columns else "NO"
        in_main = "YES" if col in main_df.columns else "NO"
        log(f"  {col:<20s}  | In Master: {in_ref:<3s}  | In Main: {in_main:<3s}")

    # ---- Confirm ----
    log("\n" + "=" * 80)
    log("CONFIRMATION")
    log("=" * 80)
    log(f"Main CSV rows:      {len(main_df)}")
    log(f"Reference rows:     {len(ref_df)}")
    log("A backup will be created automatically before processing")

    user_input = input("\n[PROMPT] Proceed with merge? (y/n): ").strip().lower()
    if user_input != 'y':
        log("Merge cancelled by user")
        save_log()
        return

    # ---- Backup ----
    backup_path = create_backup(MAIN_CSV_FILE)
    if not backup_path:
        log("Failed to create backup - aborting for safety", "ERROR")
        save_log()
        return

    # ---- Merge with retry ----
    log("\n" + "=" * 80)
    log("MERGING DATA")
    log("=" * 80)

    merged_df = None
    for attempt in range(MAX_RETRIES):
        try:
            log(f"Merge attempt {attempt + 1}/{MAX_RETRIES}")
            merged_df = perform_merge(main_df, ref_df)
            break
        except Exception as e:
            log(f"Merge attempt {attempt + 1} failed: {e}", "ERROR")
            if attempt < MAX_RETRIES - 1:
                log(f"Retrying in {RETRY_DELAY} seconds...")
                time.sleep(RETRY_DELAY)
            else:
                log("Max retries reached - merge failed", "ERROR")
                save_log()
                return

    if merged_df is None:
        log("Merge returned no data", "ERROR")
        save_log()
        return

    # ---- Write output ----
    log("\n" + "=" * 80)
    log("WRITING OUTPUT")
    log("=" * 80)

    for attempt in range(MAX_RETRIES):
        try:
            merged_df.to_csv(OUTPUT_CSV_FILE, index=False, encoding='utf-8-sig')  # utf-8-sig for Excel compatibility
            size_mb = os.path.getsize(OUTPUT_CSV_FILE) / 1024 / 1024
            log(f"Output written: {OUTPUT_CSV_FILE} ({size_mb:.2f} MB)", "SUCCESS")
            break
        except PermissionError:
            log(f"Cannot write output (file locked). Retrying in {RETRY_DELAY}s...", "WARNING")
            time.sleep(RETRY_DELAY)
            if attempt == MAX_RETRIES - 1:
                log("Failed to write output file", "ERROR")
                save_log()
                return

    # ---- Verification ----
    log("\n" + "=" * 80)
    log("VERIFICATION")
    log("=" * 80)

    verify_df = pd.read_csv(OUTPUT_CSV_FILE, encoding='utf-8-sig', dtype=str, keep_default_na=False, nrows=5)
    verify_df.columns = verify_df.columns.str.strip()

    for col in COLUMNS_TO_UPDATE:
        if col in verify_df.columns:
            sample = verify_df[col].head(3).tolist()
            log(f"  {col:<20s}: {sample}")
        else:
            log(f"  {col:<20s}: *** MISSING FROM OUTPUT ***", "ERROR")

    log(f"\nMain CSV rows:   {len(main_df)}")
    log(f"Output rows:     {len(merged_df)}")
    if len(main_df) != len(merged_df):
        log("WARNING: Row count mismatch! Check for duplicate keys.", "WARNING")
    else:
        log("Row count matches - no data loss", "SUCCESS")

    log(f"\nBackup saved at: {backup_path}")
    log("IMPORTANT: Verify the output before deleting the backup!", "WARNING")

    save_log()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log("\nScript interrupted by user", "WARNING")
        save_log()
    except Exception as e:
        log(f"\nScript failed with error: {e}", "ERROR")
        import traceback
        traceback.print_exc()
        save_log()
