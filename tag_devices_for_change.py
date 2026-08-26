#!/usr/bin/env python3
"""
Add or remove a list of devices (by IP) from an EXISTING Catalyst Center
tag, for scoping a specific change (e.g. "these 80 switches are part of
change CHANGE-2026-08-25-1234"). Create the tag itself manually first
(Provision > Tag, or Design > Tag) - this script only populates/clears
membership, since that's the tedious/error-prone-by-hand part for a large
device list.

Deliberately NOT implemented (schema not confirmed, low priority given
your stated workflow):
    - Creating or deleting the tag itself (Create Tag / Delete Tag)
If you want this automated later, paste its schema doc the same way you
did for the membership operations and I'll add it precisely.

'memberType="networkdevice"' is confirmed correct - verified live against
GET /dna/intent/api/v1/tag/member/type (--list-member-types reproduces
this check). A real add-run initially failed with "One or more member
ids does not exist" despite that; the actual bug was memberToTags being
built backwards ({tagId: [deviceIds]} instead of {deviceId: [tagId]} -
the field name reads "member to tags", i.e. keyed by member, not by
tag), which made Catalyst Center look up the tag's own UUID as if it
were a device id. Fixed - see add_devices_to_tag().

Workflow (add, the default):
    1. Authenticate                POST /dna/system/api/v1/auth/token
    2. Read IP list from the input file
    3. Resolve IP -> device        GET  /dna/intent/api/v1/network-device/ip-address/<ip>
    4. Resolve tag name -> tag id  GET  /dna/intent/api/v1/tag?name=<name>
    5. Add all devices to the tag  PUT  /dna/intent/api/v1/tag/member
                                    body: {"memberType": "networkdevice",
                                           "memberToTags": {"<deviceId>": [tagId], ...}}
    6. Print a summary

Workflow (--remove):
    Same steps 1-4, then for EACH device individually (this endpoint has
    no bulk form, unlike the add operation):
    5. Remove from the tag  DELETE /dna/intent/api/v1/tag/<tagId>/member/<deviceId>
    6. Print a per-device summary (this endpoint gives real per-device
       success/failure, unlike the single shared trigger the add path uses)

Usage:
    python tag_devices_for_change.py --file devices.csv --tag-name CHANGE-2026-08-25-1234 --dry-run
    python tag_devices_for_change.py --file devices.csv --tag-name CHANGE-2026-08-25-1234 --insecure
    python tag_devices_for_change.py --file devices.csv --tag-name CHANGE-2026-08-25-1234 --insecure --remove

Credentials and host are taken from (highest priority first):
    1. command-line flags --host / --username / --password
    2. environment variables DNAC_HOST / DNAC_USER / DNAC_PASSWORD
    3. a .env (or credential.env) file in the same folder as this script

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
MEMBER_TYPE = "networkdevice"  # best-effort guess - see docstring
TASK_POLL_INTERVAL = 5
TASK_POLL_TIMEOUT = 120
REMOVE_PAUSE = 1   # seconds between per-device removal calls


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
    p = argparse.ArgumentParser(description="Add devices to an existing Catalyst Center tag, by IP.")
    p.add_argument("--host", default=os.environ.get("DNAC_HOST"),
                   help="Catalyst Center hostname or IP, no scheme (or set DNAC_HOST)")
    p.add_argument("--file", help="Input .xlsx or .csv file with an 'IP Address' column (not needed with --list-member-types)")
    p.add_argument("--tag-name", help="Name of the EXISTING tag to add devices to (not needed with --list-member-types)")
    p.add_argument("--username", default=os.environ.get("DNAC_USER"), help="API username (or set DNAC_USER)")
    p.add_argument("--password", default=os.environ.get("DNAC_PASSWORD"), help="API password (or set DNAC_PASSWORD)")
    p.add_argument("--insecure", "-k", action="store_true", help="Skip TLS certificate verification (self-signed labs)")
    p.add_argument("--dry-run", action="store_true", help="Resolve devices and the tag but do not change membership")
    p.add_argument("--remove", action="store_true",
                   help="Remove the devices from the tag instead of adding them")
    p.add_argument("--list-member-types", action="store_true",
                   help="Print the real valid memberType values from GET /tag/member/type, then exit")
    args = p.parse_args()

    if not args.host:
        args.host = input("Catalyst Center host/IP: ")
    if not args.username:
        args.username = input("Catalyst Center username: ")
    if not args.password:
        args.password = getpass.getpass("Catalyst Center password: ")
    if not args.list_member_types and not (args.file and args.tag_name):
        sys.exit("ERROR: --file and --tag-name are required unless --list-member-types is used")
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

    # -- Step 4: tag name -> tag id -------------------------------------------
    def get_tag_id(self, name):
        """Return the tag's id, or None if no tag with this name exists."""
        r = self.session.get(
            f"{self.base}/dna/intent/api/v1/tag",
            params={"name": name},
            timeout=30,
        )
        r.raise_for_status()
        tags = r.json().get("response") or []
        if not tags:
            return None
        return tags[0].get("id")

    def get_member_types(self):
        """Return the raw list of valid memberType values, per the doc's own
        pointer ('queryable via GET /tag/member/type')."""
        r = self.session.get(f"{self.base}/dna/intent/api/v1/tag/member/type", timeout=30)
        r.raise_for_status()
        return r.json().get("response") or r.json()

    # -- Step 5: add devices to the tag ---------------------------------------
    def add_devices_to_tag(self, tag_id, device_ids):
        # memberToTags maps MEMBER id -> list of TAG ids (the field name reads
        # "member to tags"), not the other way around. Getting this backwards
        # ({tagId: [deviceIds]}) makes Catalyst Center look up the tag's own
        # UUID as if it were a device id, producing "member ids does not
        # exist" even though memberType and the device ids were both fine.
        body = {"memberType": MEMBER_TYPE, "memberToTags": {device_id: [tag_id] for device_id in device_ids}}
        r = self.session.put(
            f"{self.base}/dna/intent/api/v1/tag/member",
            json=body,
            timeout=60,
        )
        r.raise_for_status()
        return r.json()

    # -- (--remove) remove one device from the tag ---------------------------
    def remove_device_from_tag(self, tag_id, device_id):
        # No request body for this one - just path parameters, and it's
        # scoped to a single member per call (no bulk form like the add).
        r = self.session.delete(
            f"{self.base}/dna/intent/api/v1/tag/{tag_id}/member/{device_id}",
            timeout=30,
        )
        r.raise_for_status()
        return r.json()

    # -- Step 6: poll the classic task API to confirm the add actually worked --
    def wait_for_task(self, task_id):
        deadline = time.time() + TASK_POLL_TIMEOUT
        while time.time() < deadline:
            r = self.session.get(f"{self.base}/dna/intent/api/v1/task/{task_id}", timeout=30)
            r.raise_for_status()
            task = r.json().get("response") or {}
            if task.get("isError"):
                return {"status": "FAILED", "detail": task.get("failureReason") or str(task)}
            if task.get("endTime"):
                return {"status": "SUCCESS", "detail": task.get("progress") or ""}
            time.sleep(TASK_POLL_INTERVAL)
        return {"status": "TIMEOUT", "detail": f"no result after {TASK_POLL_TIMEOUT}s"}


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


# -- Step 2: read the input file for IP addresses ----------------------------
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

    print(f"Connecting to https://{normalize_host(args.host)} ...")
    dnac = DnacClient(args.host, args.username, args.password, verify=not args.insecure)
    print("Authenticated OK\n")

    if args.list_member_types:
        print("Real valid memberType values from GET /dna/intent/api/v1/tag/member/type:")
        print(dnac.get_member_types())
        return

    ips = list(read_ips(args.file))
    if not ips:
        sys.exit(f"ERROR: no usable rows found in {args.file}")
    print(f"Loaded {len(ips)} device IP(s) from {args.file}\n")

    tag_id = dnac.get_tag_id(args.tag_name)
    if not tag_id:
        sys.exit(f"ERROR: no tag named '{args.tag_name}' found - create it first via the GUI "
                 f"(Design/Provision > Tag), then re-run this script.")
    print(f"Tag '{args.tag_name}' -> tagId {tag_id}\n")

    devices = []   # (ip, device_id, hostname)
    skipped = []
    for ip in ips:
        device = dnac.get_device_by_ip(ip)
        if device is None:
            print(f"!! {ip}: not found in inventory - skipping")
            skipped.append((ip, "device not in inventory"))
            continue
        device_id, hostname = device.get("id"), device.get("hostname", ip)
        print(f"ok {ip}: {hostname} -> deviceId {device_id}")
        devices.append((ip, device_id, hostname))
    print()

    if not devices:
        sys.exit("ERROR: no devices resolved to inventory entries - nothing to tag.")

    device_ids = [d[1] for d in devices]
    action = "remove" if args.remove else "add"

    if args.dry_run:
        print(f"[dry-run] would {action} {len(device_ids)} device(s) "
              f"{'from' if args.remove else 'to'} tag '{args.tag_name}' ({tag_id}):")
        for ip, device_id, hostname in devices:
            print(f"  {ip} ({hostname})")
        sys.exit(0)

    if args.remove:
        print(f"Removing {len(device_ids)} device(s) from tag '{args.tag_name}', one at a time "
              f"(this endpoint has no bulk form)...\n")
        ok, failed = [], []
        for idx, (ip, device_id, hostname) in enumerate(devices, 1):
            print(f"[{idx}/{len(devices)}] {ip} ({hostname})...")
            try:
                result = dnac.remove_device_from_tag(tag_id, device_id)
                print(f"  raw response: {result}")
                ok.append((ip, hostname))
            except requests.HTTPError as exc:
                detail = http_error_detail(exc)
                print(f"  !! remove failed: {detail}")
                failed.append((ip, hostname, detail))
            if idx < len(devices):
                time.sleep(REMOVE_PAUSE)

        print("\n" + "=" * 60)
        print(f"Summary: {len(ok)} device(s) removed from tag '{args.tag_name}', "
              f"{len(failed)} failed, {len(skipped)} skipped")
        for ip, hostname, reason in failed:
            print(f"  FAILED  {ip} ({hostname}): {reason}")
        for ip, reason in skipped:
            print(f"  SKIPPED {ip}: {reason}")
        sys.exit(1 if failed else 0)

    print(f"Adding {len(device_ids)} device(s) to tag '{args.tag_name}'...")
    try:
        result = dnac.add_devices_to_tag(tag_id, device_ids)
    except requests.HTTPError as exc:
        sys.exit(f"ERROR: add-to-tag request failed: {http_error_detail(exc)}")
    print(f"  raw trigger response: {result}")

    task_id = (result.get("response") or {}).get("taskId") or result.get("taskId")
    if not task_id:
        sys.exit(f"ERROR: no taskId returned - raw response: {result}")
    print(f"  taskId: {task_id} - polling to confirm it actually succeeded...")

    task_result = dnac.wait_for_task(task_id)
    status = task_result["status"]
    detail = task_result["detail"]

    print("\n" + "=" * 60)
    if status == "SUCCESS":
        print(f"=> tag membership update {status.lower()}: {detail}")
        print(f"Summary: {len(devices)} device(s) added to tag '{args.tag_name}', {len(skipped)} skipped")
    else:
        print(f"!! tag membership update {status.lower()}: {detail}")
        print(f"Summary: 0 device(s) confirmed added to tag '{args.tag_name}', {len(skipped)} skipped")
    for ip, reason in skipped:
        print(f"  SKIPPED {ip}: {reason}")
    sys.exit(1 if status != "SUCCESS" else 0)


if __name__ == "__main__":
    main()
