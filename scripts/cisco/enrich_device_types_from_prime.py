#!/usr/bin/env python3
"""
Fills gaps in a cisco_detect_device_os.py "device_types.csv" report by
looking up each device's IP in a Cisco Prime Infrastructure device
export CSV (a "VLOOKUP" on IP address) and backfilling any Unknown /
blank fields from Prime's inventory data.

Usage:
    py enrich_device_types_from_prime.py --prime "Prime_DC_.csv" \
        [--device-types "reports/cisco/device_discovery/device_types.csv"] \
        [--output "reports/cisco/device_discovery/device_types_enriched.csv"]
"""

import argparse
import csv
import os
import re

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, "..", ".."))
DEFAULT_DEVICE_TYPES = os.path.join(PROJECT_ROOT, "reports", "cisco", "device_discovery", "device_types.csv")

# Fields in device_types.csv that get backfilled from Prime, and the Prime
# column each one is sourced from.
FIELD_SOURCES = {
    'hostname': 'Device Name',
    'os_type': 'Software Type',
    'model': 'Model Number',
    'version': 'Software Version',
    'serial': 'Serial Number',
}

UNKNOWN_VALUES = {'', 'unknown', 'n/a', 'none'}


def is_unknown(value):
    return (value or '').strip().lower() in UNKNOWN_VALUES


def classify_device_family(device_type_text, model_number):
    """
    Best-effort hardware family classification from Prime's free-text
    "Device Type" column and "Model Number", mirroring the logic
    cisco_detect_device_os.py applies to live 'show version' output.
    """
    text = f"{device_type_text or ''} {model_number or ''}".lower()
    model_upper = (model_number or '').upper()

    if 'nexus' in text or re.match(r'^N\d', model_upper):
        return 'Nexus'
    if 'catalyst' in text or model_upper.startswith(('WS-C', 'C9', 'C3', 'C2')):
        return 'Catalyst'
    if 'adaptive security appliance' in text or model_upper.startswith('ASA'):
        return 'ASA'
    if model_upper.startswith('ASR') or re.search(r'\basr\b', text):
        return 'ASR'
    if 'integrated services router' in text or model_upper.startswith(('ISR', 'C8')):
        return 'ISR'
    if model_upper.startswith('NCS') or re.search(r'\bncs\b', text):
        return 'NCS'
    if 'voice gateway' in text:
        return 'Voice Gateway'
    if 'wireless' in text or 'wlc' in text:
        return 'WLC'
    return 'Unknown'


def load_prime_export(path):
    """
    Returns {ip: prime_row_dict} keyed by the "IP Address" column.
    """
    lookup = {}
    with open(path, 'r', newline='', encoding='utf-8-sig') as f:
        reader = csv.DictReader(f)
        if 'IP Address' not in (reader.fieldnames or []):
            raise ValueError(
                f"'{path}' doesn't look like a Prime export - no 'IP Address' column found. "
                f"Columns seen: {reader.fieldnames}"
            )
        for row in reader:
            ip = (row.get('IP Address') or '').strip()
            if ip:
                lookup[ip] = row
    return lookup


def clean_hostname(device_name):
    device_name = (device_name or '').strip()
    if not device_name:
        return ''
    # Prime sometimes stores FQDNs (e.g. "HOST01.ngco.com"); the live
    # detector only ever captures the bare hostname from the device
    # prompt, so strip any domain suffix for consistency.
    return device_name.split('.')[0]


def enrich_row(row, prime_lookup):
    """
    Fills any Unknown/blank fields in `row` using the matching Prime
    record for row['ip']. Returns (row, filled_fields: list[str],
    matched_in_prime: bool).
    """
    ip = (row.get('ip') or '').strip()
    prime_row = prime_lookup.get(ip)
    filled = []

    if prime_row is None:
        return row, filled, False

    for field, prime_column in FIELD_SOURCES.items():
        if not is_unknown(row.get(field)):
            continue
        prime_value = (prime_row.get(prime_column) or '').strip()
        if field == 'hostname':
            prime_value = clean_hostname(prime_value)
        if prime_value:
            row[field] = prime_value
            filled.append(field)

    if is_unknown(row.get('device_family')):
        family = classify_device_family(prime_row.get('Device Type'), prime_row.get('Model Number'))
        if family != 'Unknown':
            row['device_family'] = family
            filled.append('device_family')

    return row, filled, True


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--prime', required=True, help='Path to the Cisco Prime Infrastructure device export CSV')
    parser.add_argument('--device-types', default=DEFAULT_DEVICE_TYPES,
                         help=f'Path to device_types.csv (default: {DEFAULT_DEVICE_TYPES})')
    parser.add_argument('--output', default=None,
                         help='Output CSV path (default: <device-types>_enriched.csv next to the input)')
    args = parser.parse_args()

    if not os.path.exists(args.device_types):
        raise FileNotFoundError(f"device_types.csv not found: {args.device_types}")
    if not os.path.exists(args.prime):
        raise FileNotFoundError(f"Prime export not found: {args.prime}")

    output_path = args.output
    if not output_path:
        base, ext = os.path.splitext(args.device_types)
        output_path = f"{base}_enriched{ext}"

    print(f"Loading Prime export: {args.prime}")
    prime_lookup = load_prime_export(args.prime)
    print(f"  {len(prime_lookup)} devices indexed by IP\n")

    with open(args.device_types, 'r', newline='', encoding='utf-8-sig') as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        fieldnames = list(reader.fieldnames or [])

    if 'enriched_from_prime' not in fieldnames:
        fieldnames.append('enriched_from_prime')

    matched_count = 0
    enriched_count = 0
    still_unknown_count = 0

    for row in rows:
        row, filled, matched = enrich_row(row, prime_lookup)
        if matched:
            matched_count += 1
        if filled:
            enriched_count += 1
            row['enriched_from_prime'] = ';'.join(filled)
        else:
            row.setdefault('enriched_from_prime', '')
        if any(is_unknown(row.get(f)) for f in list(FIELD_SOURCES) + ['device_family']):
            still_unknown_count += 1

    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(rows)

    print(f"Total devices in device_types.csv: {len(rows)}")
    print(f"Matched against Prime by IP:        {matched_count}")
    print(f"Rows with at least one field filled: {enriched_count}")
    print(f"Rows still missing some field(s):    {still_unknown_count}")
    print(f"\n✓ Enriched report written to: {output_path}")


if __name__ == "__main__":
    main()
