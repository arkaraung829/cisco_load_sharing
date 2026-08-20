#!/usr/bin/env python3
"""
Run 'show cdp neighbors detail' on a list of Catalyst Center switches (via
the Command Runner API) and export every neighbor entry to a CSV.

Reads an Excel (.xlsx) or CSV file with at least an "IP Address" column
(any other columns, e.g. Device Family / Site, are ignored).

Workflow (all steps automated):
    1. Authenticate            POST /dna/system/api/v1/auth/token
    2. Read IP list from the input file
    3. Resolve IP -> device    GET  /dna/intent/api/v1/network-device/ip-address/<ip>
    4. Run the CLI command     POST /dna/intent/api/v1/network-device-poller/cli/read-request
                                (all devices in ONE call)
    5. Poll the task           GET  /dna/intent/api/v1/task/<taskId>
    6. Fetch raw CLI output    GET  /dna/intent/api/v1/file/<fileId>
    7. Parse each device's 'show cdp neighbors detail' text into rows
    8. Resolve each neighbor's hostname via reverse DNS (best-effort)
    9. Write cdp_neighbors_results.csv:
           Source Device, Neighbor ID, Neighbor IP, Platform, Hostname

Usage:
    python cdp_neighbors_detail.py --file devices.xlsx
    python cdp_neighbors_detail.py --file devices.csv --insecure

Credentials and host are taken from (highest priority first):
    1. command-line flags --host / --username / --password
    2. environment variables DNAC_HOST / DNAC_USER / DNAC_PASSWORD
    3. a .env (or credential.env) file in the same folder as this script
Anything still missing is prompted for interactively (password hidden).

Requires: requests. For .xlsx input also: openpyxl (CSV needs nothing extra).
"""

import argparse
import csv
import getpass
import json
import os
import re
import socket
import sys
import time

import requests
import urllib3

COL_IP = "ip address"
COMMAND = "show cdp neighbors detail"

REQUEST_RETRIES = 3      # extra attempts when Catalyst Center returns 429/5xx
RETRY_DELAY = 15         # seconds before first retry (doubles each attempt)
TASK_POLL_INTERVAL = 5   # seconds between task-status polls
TASK_POLL_TIMEOUT = 300  # give up polling after this many seconds
DNS_TIMEOUT = 3          # seconds to wait for each reverse-DNS lookup
BATCH_SIZE = 20          # Command Runner's documented limit: max 5 commands x 20 devices per request
BATCH_PAUSE = 2          # seconds between batches

OUTPUT_FILE = "cdp_neighbors_results.csv"


def load_dotenv():
    """Load KEY=VALUE pairs from a .env (or credential.env) file next to this
    script into os.environ. Real environment variables take priority."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    env_path = next((p for p in (os.path.join(script_dir, name) for name in (".env", "credential.env"))
                     if os.path.isfile(p)), None)
    if env_path is None:
        return
    with open(env_path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key, value = key.strip(), value.strip().strip("'\"")
            if key and key not in os.environ:
                os.environ[key] = value


def parse_args():
    load_dotenv()
    p = argparse.ArgumentParser(description="Collect CDP neighbor detail from Catalyst Center devices via Command Runner.")
    p.add_argument("--host", default=os.environ.get("DNAC_HOST"),
                   help="Catalyst Center hostname or IP, no scheme (or set DNAC_HOST)")
    p.add_argument("--file", required=True, help="Input .xlsx or .csv file with an 'IP Address' column")
    p.add_argument("--username", default=os.environ.get("DNAC_USER"), help="API username (or set DNAC_USER)")
    p.add_argument("--password", default=os.environ.get("DNAC_PASSWORD"), help="API password (or set DNAC_PASSWORD)")
    p.add_argument("--insecure", "-k", action="store_true", help="Skip TLS certificate verification (self-signed labs)")
    p.add_argument("--no-dns", action="store_true", help="Skip reverse-DNS hostname resolution (faster)")
    args = p.parse_args()

    if not args.host:
        args.host = input("Catalyst Center host/IP: ")
    if not args.username:
        args.username = input("Catalyst Center username: ")
    if not args.password:
        args.password = getpass.getpass("Catalyst Center password: ")
    return args


def normalize_host(host):
    """Strip any scheme the caller already included (DNAC_HOST=https://... is
    a common credential.env mistake) so we don't end up with https://https://."""
    return re.sub(r"^\s*https?://", "", host.strip(), flags=re.IGNORECASE).rstrip("/")


class DnacClient:
    def __init__(self, host, username, password, verify=True):
        self.base = f"https://{normalize_host(host)}"
        self.verify = verify
        if not verify:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        self.session = requests.Session()
        self.session.verify = verify
        self._authenticate(username, password)

    # -- Step 1: authentication ---------------------------------------------
    def _authenticate(self, username, password):
        r = self.session.post(
            f"{self.base}/dna/system/api/v1/auth/token",
            auth=(username, password),
            timeout=30,
        )
        if r.status_code == 401:
            sys.exit("ERROR: authentication failed (401) - check username/password.")
        r.raise_for_status()
        self.session.headers.update({
            "X-Auth-Token": r.json()["Token"],
            "Content-Type": "application/json",
        })

    # -- Step 3: IP -> device record -----------------------------------------
    def get_device_by_ip(self, ip):
        """Return the inventory record for a device IP, or None if not in inventory."""
        r = self.session.get(
            f"{self.base}/dna/intent/api/v1/network-device/ip-address/{ip}",
            timeout=30,
        )
        if r.status_code in (404, 500):
            return None
        r.raise_for_status()
        return r.json().get("response") or None

    # -- Step 4: run the CLI command on all devices in one call -------------
    def run_command(self, device_ids, command):
        r = self.session.post(
            f"{self.base}/dna/intent/api/v1/network-device-poller/cli/read-request",
            json={"commands": [command], "deviceUuids": device_ids, "name": "cdp-neighbor-collection"},
            timeout=60,
        )
        r.raise_for_status()
        resp = r.json().get("response") or {}
        task_id = resp.get("taskId")
        if not task_id:
            sys.exit(f"ERROR: no taskId returned from read-request: {r.json()}")
        return task_id

    # -- Step 5: poll the task until it finishes -----------------------------
    def wait_for_task(self, task_id):
        deadline = time.time() + TASK_POLL_TIMEOUT
        while time.time() < deadline:
            r = self.session.get(f"{self.base}/dna/intent/api/v1/task/{task_id}", timeout=30)
            r.raise_for_status()
            task = r.json().get("response") or {}
            if task.get("isError"):
                sys.exit(f"ERROR: Command Runner task failed: {task.get('failureReason') or task}")
            if task.get("endTime"):
                progress = task.get("progress") or ""
                try:
                    file_id = json.loads(progress).get("fileId")
                except (ValueError, AttributeError):
                    file_id = None
                if not file_id:
                    sys.exit(f"ERROR: task finished but no fileId in progress: {progress}")
                return file_id
            time.sleep(TASK_POLL_INTERVAL)
        sys.exit(f"ERROR: Command Runner task {task_id} did not finish within {TASK_POLL_TIMEOUT}s")

    # -- Step 6: fetch the raw CLI output ------------------------------------
    def get_file(self, file_id):
        r = self.session.get(f"{self.base}/dna/intent/api/v1/file/{file_id}", timeout=60)
        r.raise_for_status()
        return r.json()


def http_error_detail(exc):
    """Pull the human-readable error out of a Catalyst Center error response."""
    resp = getattr(exc, "response", None)
    if resp is None:
        return str(exc)
    try:
        err = resp.json().get("errorResponse") or {}
    except ValueError:
        return f"HTTP {resp.status_code}: {resp.text[:500]}"
    parts = []
    bapi_msg = (err.get("bapiErrorResponse") or {}).get("bapiErrorMessage")
    if bapi_msg:
        parts.append(bapi_msg)
    for comp in err.get("componentErrorResponse") or []:
        msg = comp.get("componentErrorMessage") or comp.get("errorMessage")
        if msg:
            parts.append(msg)
    return "; ".join(parts) or f"HTTP {resp.status_code}: {resp.text[:500]}"


def run_command_with_retry(dnac, device_ids, command):
    delay = RETRY_DELAY
    for attempt in range(REQUEST_RETRIES + 1):
        try:
            return dnac.run_command(device_ids, command)
        except requests.HTTPError as exc:
            resp = exc.response
            retryable = resp is not None and resp.status_code in (429, 500, 502, 503, 504)
            if not retryable or attempt == REQUEST_RETRIES:
                raise
            print(f".. HTTP {resp.status_code} from Catalyst Center, "
                  f"waiting {delay}s then retrying ({attempt + 1}/{REQUEST_RETRIES})")
            time.sleep(delay)
            delay *= 2


# -- Step 7: parse 'show cdp neighbors detail' text into structured rows ---
def parse_cdp_neighbors_detail(text):
    """Split raw CDP output into one dict per neighbor entry."""
    blocks = re.split(r"-{5,}", text)
    entries = []
    for block in blocks:
        if "Device ID:" not in block:
            continue
        device_id = re.search(r"Device ID:\s*(\S+)", block)
        ip_addr = re.search(r"IP address:\s*([\d.]+)", block)
        platform = re.search(r"Platform:\s*(.+?),\s*Capabilities:", block)
        entries.append({
            "neighbor_id": device_id.group(1).strip() if device_id else "",
            "neighbor_ip": ip_addr.group(1).strip() if ip_addr else "",
            "platform": platform.group(1).strip() if platform else "",
        })
    return entries


def reverse_dns(ip):
    if not ip:
        return ""
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, socket.timeout):
        return ""


def chunked(seq, size):
    for i in range(0, len(seq), size):
        yield seq[i:i + size]


# -- Step 2: read the input file for IP addresses ---------------------------
def read_ips(path):
    """Yield IP addresses from an .xlsx or .csv file with an 'IP Address' column."""
    if path.lower().endswith(".xlsx"):
        try:
            from openpyxl import load_workbook
        except ImportError:
            sys.exit("ERROR: reading .xlsx needs openpyxl - run: pip install openpyxl "
                     "(or export the sheet as CSV instead)")
        ws = load_workbook(path, read_only=True, data_only=True).active
        rows = ([("" if c is None else str(c).strip()) for c in row]
                for row in ws.iter_rows(values_only=True))
    else:
        rows = ([c.strip() for c in row] for row in csv.reader(open(path, newline="")))

    header = next(rows, None)
    if not header:
        sys.exit(f"ERROR: {path} is empty.")
    lowered = [h.lower() for h in header]
    try:
        ip_col = lowered.index(COL_IP)
    except ValueError:
        sys.exit(f"ERROR: {path} must have an '{COL_IP}' column header (found: {header})")

    seen = set()
    for row in rows:
        if len(row) <= ip_col:
            continue
        ip = row[ip_col]
        if ip and ip not in seen:
            seen.add(ip)
            yield ip


def main():
    args = parse_args()
    socket.setdefaulttimeout(DNS_TIMEOUT)

    ips = list(read_ips(args.file))
    if not ips:
        sys.exit(f"ERROR: no usable rows found in {args.file}")
    print(f"Loaded {len(ips)} device IP(s) from {args.file}\n")

    print(f"Connecting to https://{normalize_host(args.host)} ...")
    dnac = DnacClient(args.host, args.username, args.password, verify=not args.insecure)
    print("Authenticated OK\n")

    devices = []   # (ip, device_id, hostname)
    skipped = []
    for ip in ips:
        device = dnac.get_device_by_ip(ip)
        if device is None:
            print(f"!! {ip}: not found in inventory - skipping")
            skipped.append(ip)
            continue
        device_id, hostname = device.get("id"), device.get("hostname", ip)
        print(f"ok {ip}: {hostname} -> deviceId {device_id}")
        devices.append((ip, device_id, hostname))
    print()

    if not devices:
        sys.exit("ERROR: no devices resolved to inventory entries - nothing to query.")

    device_ids = [d[1] for d in devices]
    id_to_source = {d[1]: (d[0], d[2]) for d in devices}

    batches = list(chunked(device_ids, BATCH_SIZE))
    print(f"Running '{COMMAND}' on {len(device_ids)} device(s) in {len(batches)} "
          f"batch(es) of up to {BATCH_SIZE} (Command Runner's per-request device limit)...")
    file_results = []
    for i, batch in enumerate(batches, 1):
        print(f"\nBatch {i}/{len(batches)} ({len(batch)} device(s))...")
        try:
            task_id = run_command_with_retry(dnac, batch, COMMAND)
        except requests.HTTPError as exc:
            print(f"  !! Command Runner request failed for this batch: {http_error_detail(exc)}")
            continue
        print(f"  taskId: {task_id} - waiting for completion...")
        file_id = dnac.wait_for_task(task_id)
        batch_results = dnac.get_file(file_id)
        if not batch_results:
            print(f"  !! no content returned for this batch")
        else:
            file_results.extend(batch_results)
        if i < len(batches):
            time.sleep(BATCH_PAUSE)
    print("\nAll batches retrieved.\n")

    dns_cache = {}
    rows = []
    empty_devices = []
    for entry in file_results:
        dev_uuid = entry.get("deviceUuid")
        source_ip, source_hostname = id_to_source.get(dev_uuid, ("?", dev_uuid or "?"))
        command_responses = entry.get("commandResponses") or {}
        raw = (command_responses.get("SUCCESS") or {}).get(COMMAND)
        if not raw:
            err = (command_responses.get("FAILURE") or {}).get(COMMAND) \
                or (command_responses.get("BLACKLISTED") or {}).get(COMMAND) \
                or "no output returned"
            print(f"!! {source_hostname} ({source_ip}): {err}")
            continue

        neighbors = parse_cdp_neighbors_detail(raw)
        if not neighbors:
            empty_devices.append(source_hostname)
            continue

        for n in neighbors:
            hostname = ""
            if not args.no_dns and n["neighbor_ip"]:
                if n["neighbor_ip"] not in dns_cache:
                    dns_cache[n["neighbor_ip"]] = reverse_dns(n["neighbor_ip"])
                hostname = dns_cache[n["neighbor_ip"]]
            rows.append([source_hostname, n["neighbor_id"], n["neighbor_ip"], n["platform"], hostname])
            print(f"{source_hostname} -> {n['neighbor_id']} ({n['neighbor_ip']}) [{n['platform']}] hostname={hostname}")

    script_dir = os.path.dirname(os.path.abspath(__file__))
    output_path = os.path.join(script_dir, OUTPUT_FILE)
    with open(output_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Source Device", "Neighbor ID", "Neighbor IP", "Platform", "Hostname"])
        writer.writerows(rows)

    print("\n" + "=" * 60)
    print(f"Wrote {len(rows)} neighbor entries to {output_path}")
    if empty_devices:
        print(f"{len(empty_devices)} device(s) had no CDP neighbors: {', '.join(empty_devices)}")
    if skipped:
        print(f"{len(skipped)} IP(s) skipped (not in inventory): {', '.join(skipped)}")


if __name__ == "__main__":
    main()
