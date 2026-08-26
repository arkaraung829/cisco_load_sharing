#!/usr/bin/env python3
"""
Add a list of devices (by IP) to an EXISTING Catalyst Center tag, for
scoping a specific change (e.g. "these 80 switches are part of change
CHANGE-2026-08-25-1234"). Create the tag itself manually first (Provision
> Tag, or Design > Tag) - this script only populates membership, since
that's the tedious/error-prone-by-hand part for a large device list.
Remove the tag (or its membership) manually once the change is done,
per your own plan.

Deliberately NOT implemented (schemas not confirmed, low priority given
your stated workflow):
    - Creating the tag itself (Create Tag)
    - Deleting the tag or removing membership (Delete Tag / Remove Tag member)
If you want these automated later, paste their schema docs the same way
you did for 'Update tag membership' and I'll add them precisely.

One field is a best-effort guess, not confirmed: 'memberType' is sent as
"networkdevice" - the API doc says valid values are queryable via
GET /dna/intent/api/v1/tag/member/type, which hasn't been checked yet.
This is low-risk to get wrong (the call just errors, no device is
touched), but if it fails, run --dry-run to confirm the rest works, then
share the actual error and I'll adjust the value.

Workflow:
    1. Authenticate                POST /dna/system/api/v1/auth/token
    2. Read IP list from the input file
    3. Resolve IP -> device        GET  /dna/intent/api/v1/network-device/ip-address/<ip>
    4. Resolve tag name -> tag id  GET  /dna/intent/api/v1/tag?name=<name>
    5. Add all devices to the tag  PUT  /dna/intent/api/v1/tag/member
                                    body: {"memberType": "networkdevice",
                                           "memberToTags": {"<tagId>": [deviceIds...]}}
    6. Print a summary

Usage:
    python tag_devices_for_change.py --file devices.csv --tag-name CHANGE-2026-08-25-1234 --dry-run
    python tag_devices_for_change.py --file devices.csv --tag-name CHANGE-2026-08-25-1234 --insecure

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

import requests
import urllib3

COL_IP = "ip address"
MEMBER_TYPE = "networkdevice"  # best-effort guess - see docstring


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
    p.add_argument("--file", required=True, help="Input .xlsx or .csv file with an 'IP Address' column")
    p.add_argument("--tag-name", required=True, help="Name of the EXISTING tag to add devices to (create it first via the GUI)")
    p.add_argument("--username", default=os.environ.get("DNAC_USER"), help="API username (or set DNAC_USER)")
    p.add_argument("--password", default=os.environ.get("DNAC_PASSWORD"), help="API password (or set DNAC_PASSWORD)")
    p.add_argument("--insecure", "-k", action="store_true", help="Skip TLS certificate verification (self-signed labs)")
    p.add_argument("--dry-run", action="store_true", help="Resolve devices and the tag but do not add anyone to it")
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

    # -- Step 5: add devices to the tag ---------------------------------------
    def add_devices_to_tag(self, tag_id, device_ids):
        body = {"memberType": MEMBER_TYPE, "memberToTags": {tag_id: device_ids}}
        r = self.session.put(
            f"{self.base}/dna/intent/api/v1/tag/member",
            json=body,
            timeout=60,
        )
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

    ips = list(read_ips(args.file))
    if not ips:
        sys.exit(f"ERROR: no usable rows found in {args.file}")
    print(f"Loaded {len(ips)} device IP(s) from {args.file}\n")

    print(f"Connecting to https://{normalize_host(args.host)} ...")
    dnac = DnacClient(args.host, args.username, args.password, verify=not args.insecure)
    print("Authenticated OK\n")

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

    if args.dry_run:
        print(f"[dry-run] would add {len(device_ids)} device(s) to tag '{args.tag_name}' ({tag_id}):")
        for ip, device_id, hostname in devices:
            print(f"  {ip} ({hostname})")
        sys.exit(0)

    print(f"Adding {len(device_ids)} device(s) to tag '{args.tag_name}'...")
    try:
        result = dnac.add_devices_to_tag(tag_id, device_ids)
    except requests.HTTPError as exc:
        sys.exit(f"ERROR: add-to-tag request failed: {http_error_detail(exc)}\n"
                 f"(memberType='{MEMBER_TYPE}' is a best-effort guess - if this error suggests an "
                 f"invalid memberType, check GET /dna/intent/api/v1/tag/member/type for the real value.)")
    print(f"  raw response: {result}")

    print("\n" + "=" * 60)
    print(f"Summary: {len(devices)} device(s) added to tag '{args.tag_name}', {len(skipped)} skipped")
    for ip, reason in skipped:
        print(f"  SKIPPED {ip}: {reason}")


if __name__ == "__main__":
    main()
