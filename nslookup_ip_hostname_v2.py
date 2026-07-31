"""Reverse-DNS lookup for a list of IPs.

Reads its input and writes its output in the SAME folder as this script.

    nslookup_ips.txt      (input,  one IP per line)
    nslookup_results.csv  (output, IP Address / Hostname)

Usage:
    py nslookup_ip_hostname_v2.py                 # uses nslookup_ips.txt beside the script
    py nslookup_ip_hostname_v2.py other_ips.txt   # optional: a different input file
"""

import socket
import csv
import os
import sys
from concurrent.futures import ThreadPoolExecutor

# ---- Path Setup ----
# Everything lives next to this script; no data/ or reports/ folders involved.
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
INPUT_FILE = sys.argv[1] if len(sys.argv) > 1 else os.path.join(SCRIPT_DIR, 'nslookup_ips.txt')
OUTPUT_FILE = os.path.join(SCRIPT_DIR, 'nslookup_results.csv')


def nslookup(ip_address):
    try:
        hostname = socket.gethostbyaddr(ip_address)[0]
        return (ip_address, hostname)
    except (socket.herror, socket.gaierror):
        return (ip_address, '')


print(f"Script   : {os.path.abspath(__file__)}")
print(f"Reading  : {INPUT_FILE}")

if not os.path.isfile(INPUT_FILE):
    sys.exit(f"ERROR: input file not found. Put nslookup_ips.txt in {SCRIPT_DIR}")

# Read IP addresses from the text file (blank lines skipped)
with open(INPUT_FILE, 'r') as file:
    ip_addresses = [line.strip() for line in file if line.strip()]

print(f"Looking up {len(ip_addresses)} IP address(es)...\n")

# Open a CSV file to write the results
with open(OUTPUT_FILE, 'w', newline='') as csvfile:
    csvwriter = csv.writer(csvfile)
    csvwriter.writerow(['IP Address', 'Hostname'])

    # Reverse DNS lookup in parallel, writing each result to the CSV
    with ThreadPoolExecutor(max_workers=30) as executor:
        for result in executor.map(nslookup, ip_addresses):
            print(f"{result[0]} -> {result[1]}")
            csvwriter.writerow(result)

print(f"\nNSLookup results have been written to {OUTPUT_FILE}")
