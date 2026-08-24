#!/usr/bin/env python3
"""
Distribute (stage) the tagged Golden software image onto Catalyst Center
devices, by IP address. This ONLY distributes the image to device flash -
it never activates/applies it. Activation is a separate API call and is
deliberately not implemented here.

Reads an Excel (.xlsx) or CSV file with at least an "IP Address" column
(any other columns, e.g. Device Family / Site, are ignored).

Workflow (all steps automated):
    1. Authenticate             POST /dna/system/api/v1/auth/token
    2. Read IP list from the input file
    3. Resolve IP -> device     GET  /dna/intent/api/v1/network-device/ip-address/<ip>
    4. Trigger ALL devices      POST /dna/intent/api/v1/networkDeviceImages/<deviceId>/distribute
                                 one call PER device (paced with a short pause + retry/backoff),
                                 but every device is triggered before any polling starts -
                                 empty distributedImages -> Catalyst Center auto-selects the
                                 image tagged Golden for that device's family/site
    5. Poll ALL tasks together  GET  /dna/intent/api/v1/networkDeviceImageUpdates?parentId=<taskId>
                                 one shared loop checks every device's own taskId each round,
                                 so the actual image copies run in parallel on Catalyst
                                 Center's side instead of one full copy at a time
    6. Print a summary of what succeeded / failed / was skipped

Note: the bulk endpoint (/networkDeviceImages/distribute/bulk) was tried
first but returned "BAPI not found" (HTTP 404) against this Catalyst
Center deployment - that endpoint isn't registered on this version. Each
device therefore gets its own taskId (no single shared task like the bulk
endpoint would have given), which is why triggering and polling are split
into two separate phases - triggering serially but polling everything at
once keeps large runs (e.g. ~80 devices) from taking as long as N times a
single device's copy time.

No activation step is performed anywhere in this script. The legacy
/dna/intent/api/v1/image/distribution endpoint is intentionally not used -
it predates the networkDeviceImages family and lacks Golden-image
auto-selection.

Usage:
    python distribute_golden_image.py --file devices.xlsx
    python distribute_golden_image.py --file devices.csv --insecure --dry-run

Credentials and host are taken from (highest priority first):
    1. command-line flags --host / --username / --password
    2. environment variables DNAC_HOST / DNAC_USER / DNAC_PASSWORD
    3. a .env (or credential.env) file in the same folder as this script
Anything still missing is prompted for interactively (password hidden).
Keep the .env file out of git.

Requires: requests. For .xlsx input also: openpyxl (CSV needs nothing extra).
"""

import argparse
import csv
import getpass
import os
import re
import sys
import time

import requests
import urllib3

COL_IP = "ip address"

DISTRIBUTE_RETRIES = 3    # extra attempts when Catalyst Center returns 429/5xx
RETRY_DELAY = 15          # seconds before first retry (doubles each attempt)
POLL_INTERVAL = 10        # seconds between distribution-task status polls
POLL_TIMEOUT = 1800       # give up polling after this many seconds (image copy can take a while)
PAUSE_BETWEEN_DEVICES = 2 # seconds between per-device distribute calls

SUCCESS_STATUSES = {"SUCCESS", "SUCCESS_WITH_WARNINGS", "COMPLETED"}
FAILURE_STATUSES = {"FAILED", "FAILURE", "ERROR", "CANCELLED", "TIMEOUT"}
# Keys Catalyst Center might use to say which device an update record is for
DEVICE_ID_KEYS = ("networkDeviceId", "deviceId", "device_id")


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
    p = argparse.ArgumentParser(description="Distribute the Golden image to Catalyst Center devices in bulk (no activation).")
    p.add_argument("--host", default=os.environ.get("DNAC_HOST"),
                   help="Catalyst Center hostname or IP, no scheme (or set DNAC_HOST)")
    p.add_argument("--file", required=True, help="Input .xlsx or .csv file with an 'IP Address' column")
    p.add_argument("--username", default=os.environ.get("DNAC_USER"), help="API username (or set DNAC_USER)")
    p.add_argument("--password", default=os.environ.get("DNAC_PASSWORD"), help="API password (or set DNAC_PASSWORD)")
    p.add_argument("--image-id", default=None,
                   help="Optional specific software image UUID to distribute instead of "
                        "auto-selecting each device's tagged Golden image")
    p.add_argument("--insecure", "-k", action="store_true", help="Skip TLS certificate verification (self-signed labs)")
    p.add_argument("--dry-run", action="store_true", help="Resolve devices but do not trigger distribution")
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

    # -- Step 4: trigger distribution for one device (DISTRIBUTE ONLY - never activate) --
    def distribute_device(self, device_id, image_id=None):
        # Empty distributedImages -> Catalyst Center auto-picks the image
        # tagged Golden for this device's family/site (per API doc).
        body = {"distributedImages": [{"id": image_id}]} if image_id else {}
        r = self.session.post(
            f"{self.base}/dna/intent/api/v1/networkDeviceImages/{device_id}/distribute",
            json=body,
            timeout=60,
        )
        r.raise_for_status()
        return r.json()

    # -- Step 5: one non-blocking check of a single task's status -----------
    def poll_task_once(self, task_id, device_id):
        """Check whether this device's distribute task has reached a terminal
        status yet. Returns the status item if so, else None. Deliberately
        does not sleep/loop itself, so a caller tracking many devices' tasks
        (each with its own taskId, since there's no bulk endpoint here) can
        interleave checks across all of them in one shared polling loop -
        letting every device's image copy run in parallel on Catalyst
        Center's side instead of waiting for each device before starting
        the next one's copy."""
        r = self.session.get(
            f"{self.base}/dna/intent/api/v1/networkDeviceImageUpdates",
            params={"parentId": task_id},
            timeout=30,
        )
        r.raise_for_status()
        payload = r.json().get("response")
        items = payload if isinstance(payload, list) else ([payload] if payload else [])
        for item in items:
            dev_id = next((item[k] for k in DEVICE_ID_KEYS if k in item), None)
            status = str(item.get("status", "")).upper()
            if dev_id == device_id and (status in SUCCESS_STATUSES or status in FAILURE_STATUSES):
                return item
        return None


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


def distribute_with_retry(dnac, device_id, image_id):
    """Trigger one device's distribute call, retrying on transient server overload."""
    delay = RETRY_DELAY
    for attempt in range(DISTRIBUTE_RETRIES + 1):
        try:
            return dnac.distribute_device(device_id, image_id)
        except requests.HTTPError as exc:
            resp = exc.response
            retryable = resp is not None and resp.status_code in (429, 500, 502, 503, 504)
            if not retryable or attempt == DISTRIBUTE_RETRIES:
                raise
            print(f".. HTTP {resp.status_code} from Catalyst Center, "
                  f"waiting {delay}s then retrying ({attempt + 1}/{DISTRIBUTE_RETRIES})")
            time.sleep(delay)
            delay *= 2


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

    ips = list(read_ips(args.file))
    if not ips:
        sys.exit(f"ERROR: no usable rows found in {args.file}")
    print(f"Loaded {len(ips)} device IP(s) from {args.file}\n")

    print(f"Connecting to https://{normalize_host(args.host)} ...")
    dnac = DnacClient(args.host, args.username, args.password, verify=not args.insecure)
    print("Authenticated OK\n")

    devices = []   # (ip, device_id, hostname, family)
    skipped = []
    for ip in ips:
        device = dnac.get_device_by_ip(ip)
        if device is None:
            print(f"!! {ip}: not found in inventory - skipping")
            skipped.append((ip, "device not in inventory"))
            continue
        device_id, hostname, family = device.get("id"), device.get("hostname", "?"), device.get("family", "?")
        print(f"ok {ip}: {hostname} ({family}) -> deviceId {device_id}")
        devices.append((ip, device_id, hostname, family))
    print()

    if not devices:
        sys.exit("ERROR: no devices resolved to inventory entries - nothing to distribute.")

    if args.dry_run:
        print(f"[dry-run] would trigger distribution for {len(devices)} device(s) "
              f"(golden image auto-selected per device)")
        sys.exit(0)

    # Phase 1: trigger every device's distribution first (not waiting for
    # each one to finish before starting the next) so the actual image
    # copies run in parallel on Catalyst Center's side. Only the trigger
    # calls themselves are sequential/paced - the copies are not.
    print(f"Triggering distribution for {len(devices)} device(s) "
          f"(the bulk endpoint isn't available on this Catalyst Center - see docstring)...\n")

    results = {}
    task_by_device = {}   # device_id -> taskId, only for devices that triggered OK
    for idx, (ip, device_id, hostname, family) in enumerate(devices, 1):
        print(f"[{idx}/{len(devices)}] triggering {ip} ({hostname})...")
        try:
            trigger = distribute_with_retry(dnac, device_id, args.image_id)
        except requests.HTTPError as exc:
            detail = http_error_detail(exc)
            print(f"  !! distribute request failed: {detail}")
            results[device_id] = {"status": "FAILED", "detail": detail}
            if idx < len(devices):
                time.sleep(PAUSE_BETWEEN_DEVICES)
            continue

        task_id = (trigger.get("response") or {}).get("taskId") or trigger.get("taskId")
        if not task_id:
            print(f"  !! no taskId returned - raw response: {trigger}")
            results[device_id] = {"status": "FAILED", "detail": f"no taskId in response: {trigger}"}
            if idx < len(devices):
                time.sleep(PAUSE_BETWEEN_DEVICES)
            continue
        print(f"  taskId: {task_id}")
        task_by_device[device_id] = task_id
        if idx < len(devices):
            time.sleep(PAUSE_BETWEEN_DEVICES)

    # Phase 2: poll every outstanding task together in one shared loop,
    # instead of blocking on each device before triggering/checking the next.
    if task_by_device:
        print(f"\nAll {len(task_by_device)} distribution(s) triggered - waiting for all to finish "
              f"(image copies run in parallel; this can take a while for large images/WAN links)...\n")
        remaining = dict(task_by_device)
        deadline = time.time() + POLL_TIMEOUT
        while remaining and time.time() < deadline:
            for device_id, task_id in list(remaining.items()):
                item = dnac.poll_task_once(task_id, device_id)
                if item is not None:
                    results[device_id] = item
                    del remaining[device_id]
                    hostname = next(h for ip_, id_, h, f_ in devices if id_ == device_id)
                    status = str(item.get("status", "")).upper()
                    print(f"  {'=>' if status in SUCCESS_STATUSES else '!!'} {hostname}: {status.lower()}")
            if remaining:
                time.sleep(POLL_INTERVAL)
        for device_id in remaining:
            results[device_id] = {"status": "TIMEOUT", "detail": f"no terminal status after {POLL_TIMEOUT}s"}
    print()

    ok, failed = [], []
    for ip, device_id, hostname, family in devices:
        r = results.get(device_id, {"status": "UNKNOWN", "detail": "no status returned for this device"})
        status = str(r.get("status", "")).upper()
        detail = r.get("detail") or r.get("message") or ""
        if status in SUCCESS_STATUSES:
            print(f"=> {ip} ({hostname}): {status.lower()} {detail}")
            ok.append((ip, hostname))
        else:
            print(f"!! {ip} ({hostname}): {status or 'UNKNOWN'} {detail}")
            failed.append((ip, hostname, detail or str(r)))

    # -- Step 6: summary -------------------------------------------------------
    print("=" * 60)
    print(f"Summary: {len(ok)} distributed, {len(failed)} failed, {len(skipped)} skipped")
    for ip, hostname, reason in failed:
        print(f"  FAILED  {ip} ({hostname}): {reason}")
    for ip, reason in skipped:
        print(f"  SKIPPED {ip}: {reason}")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
