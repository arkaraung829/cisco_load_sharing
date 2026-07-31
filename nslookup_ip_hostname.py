import socket
import csv
import os
from concurrent.futures import ThreadPoolExecutor

# ---- Path Setup ----
# Input and output both live in the same directory as this script.
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
INPUT_FILE = os.path.join(SCRIPT_DIR, 'nslookup_ips.txt')
OUTPUT_FILE = os.path.join(SCRIPT_DIR, 'nslookup_results.csv')

def nslookup(ip_address):
    try:
        hostname = socket.gethostbyaddr(ip_address)[0]
        return (ip_address, hostname)
    except (socket.herror, socket.gaierror):
        return (ip_address, '')

# Read IP addresses from the text file next to the script (blank lines skipped)
with open(INPUT_FILE, 'r') as file:
    ip_addresses = [line.strip() for line in file if line.strip()]

# Open a CSV file to write the results
with open(OUTPUT_FILE, 'w', newline='') as csvfile:
    csvwriter = csv.writer(csvfile)
    # Write the header row
    csvwriter.writerow(['IP Address', 'Hostname'])

    # Perform reverse DNS lookup for each IP address in parallel and write the results to the CSV file
    with ThreadPoolExecutor(max_workers=30) as executor:
        results = executor.map(nslookup, ip_addresses)
        for result in results:
            print(f"{result[0]} -> {result[1]}")
            csvwriter.writerow(result)

print(f"NSLookup results have been written to {OUTPUT_FILE}")
