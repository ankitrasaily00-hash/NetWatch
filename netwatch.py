
import argparse
import csv
import json
import socket
import sys
import time

import psutil

from core.discovery import (
    enrich_devices,
    get_local_network,
    scan_network,
)

from core.ipintel import (
    get_public_ip_intelligence,
)

from core.monitor import monitor_network


# ============================================================
# BANNER
# ============================================================

BANNER = r"""
 _   _      _   _       _       _
| \ | | ___| |_| |_ __ _| |_ ___| |__
|  \| |/ _ \ __| __/ _` | __/ __| '_ \
| |\  |  __/ |_| || (_| | || (__| | | |
|_| \_|\___|\__|\__\__,_|\__\___|_| |_|

        Local Network Intelligence
"""


# ============================================================
# DISPLAY HELPERS
# ============================================================

def print_banner():
    print(BANNER)


def get_network_info():
    """
    Get information about the active network.
    """

    return get_local_network()


# ============================================================
# NETWORK INFORMATION
# ============================================================

def print_network_info():
    """
    Display active network information.
    """

    try:
        (
            local_ip,
            network,
            interface,
            gateway,
        ) = get_network_info()

        print("[+] Network Information")
        print()

        print(f"    Interface : {interface}")
        print(f"    Local IP  : {local_ip}")
        print(f"    Network   : {network}")

        print(
            f"    Gateway   : "
            f"{gateway if gateway else 'Unknown'}"
        )

    except Exception as error:
        print(
            f"[-] Unable to detect network: {error}"
        )

        return False

    return True


# ============================================================
# NETWORK INTERFACES
# ============================================================

def print_interfaces():
    """
    Display network interfaces detected by NetWatch.
    """

    interfaces = psutil.net_if_stats()
    addresses = psutil.net_if_addrs()

    print("[+] Network Interfaces")
    print()

    found = False

    for interface, stats in interfaces.items():

        status = (
            "UP"
            if stats.isup
            else "DOWN"
        )

        ipv4_addresses = []

        for address in addresses.get(
            interface,
            [],
        ):

            if address.family == socket.AF_INET:
                ipv4_addresses.append(
                    address.address
                )

        print(f"    {interface}")
        print(f"      Status : {status}")

        if ipv4_addresses:

            for ip in ipv4_addresses:
                print(
                    f"      IPv4   : {ip}"
                )

        else:
            print("      IPv4   : None")

        print()

        found = True

    if not found:
        print("    No interfaces found.")

    return found


# ============================================================
# PUBLIC IP INTELLIGENCE
# ============================================================

def print_ip_intelligence(intelligence):
    """
    Display public IP intelligence.
    """

    print("[+] Public IP Intelligence")
    print()

    if not intelligence:
        print(
            "    Status       : Unavailable"
        )
        return

    if not intelligence.get("available"):
        print(
            "    Status       : Unavailable"
        )

        error = intelligence.get("error")

        if error:
            print(
                f"    Reason       : {error}"
            )

        return

    print(
        f"    Public IP    : "
        f"{intelligence.get('public_ip', 'Unknown')}"
    )

    print(
        f"    Country      : "
        f"{intelligence.get('country', 'Unknown')}"
    )

    print(
        f"    Country Code : "
        f"{intelligence.get('country_code', 'Unknown')}"
    )

    print(
        f"    Region       : "
        f"{intelligence.get('region', 'Unknown')}"
    )

    print(
        f"    City         : "
        f"{intelligence.get('city', 'Unknown')}"
    )

    print(
        f"    Postal       : "
        f"{intelligence.get('postal', 'Unknown')}"
    )

    print(
        f"    Latitude     : "
        f"{intelligence.get('latitude', 'Unknown')}"
    )

    print(
        f"    Longitude    : "
        f"{intelligence.get('longitude', 'Unknown')}"
    )

    print(
        f"    Timezone     : "
        f"{intelligence.get('timezone', 'Unknown')}"
    )

    print(
        f"    ISP          : "
        f"{intelligence.get('isp', 'Unknown')}"
    )

    print(
        f"    Organization : "
        f"{intelligence.get('organization', 'Unknown')}"
    )

    print(
        f"    ASN          : "
        f"{intelligence.get('asn', 'Unknown')}"
    )


# ============================================================
# DEVICE ROLE
# ============================================================

def get_device_role(device, local_ip):
    """
    Determine the role of a discovered device.
    """

    if device.get("ip") == local_ip:
        return "LOCAL"

    if device.get("gateway"):
        return "GATEWAY"

    return "DEVICE"


# ============================================================
# BUILD SCAN DATA
# ============================================================

def build_scan_data(
    local_ip,
    network,
    interface,
    gateway,
    devices,
    elapsed,
    public_ip_intelligence=None,
):
    """
    Build structured scan results.

    The returned dictionary is used by JSON and CSV output.
    """

    device_data = []

    for device in devices:

        device_data.append(
            {
                "ip": device.get(
                    "ip",
                    "Unknown",
                ),

                "mac": device.get(
                    "mac",
                    "Unknown",
                ),

                "hostname": device.get(
                    "hostname",
                    "Unknown",
                ),

                "vendor": device.get(
                    "vendor",
                    "Unknown",
                ),

                "role": get_device_role(
                    device,
                    local_ip,
                ),
            }
        )

    data = {
        "network": {
            "interface": interface,
            "local_ip": local_ip,
            "network": network,
            "gateway": gateway,
        },

        "scan": {
            "devices_discovered": len(
                device_data
            ),

            "scan_time_seconds": round(
                elapsed,
                2,
            ),
        },

        "devices": device_data,
    }

    if public_ip_intelligence is not None:
        data["public_ip_intelligence"] = (
            public_ip_intelligence
        )

    return data


# ============================================================
# DEVICE TABLE
# ============================================================

def print_device_table(
    local_ip,
    devices,
):
    """
    Display discovered devices in table format.
    """

    print(
        f"{'IP ADDRESS':<17}"
        f"{'MAC ADDRESS':<20}"
        f"{'HOSTNAME':<35}"
        f"{'VENDOR':<25}"
        f"ROLE"
    )

    print("-" * 110)

    local_count = 0
    gateway_count = 0
    device_count = 0

    for device in devices:

        ip = device.get(
            "ip",
            "Unknown",
        )

        mac = device.get(
            "mac",
            "Unknown",
        )

        hostname = device.get(
            "hostname",
            "Unknown",
        )

        vendor = device.get(
            "vendor",
            "Unknown",
        )

        role = get_device_role(
            device,
            local_ip,
        )

        if role == "LOCAL":
            local_count += 1

        elif role == "GATEWAY":
            gateway_count += 1

        else:
            device_count += 1

        print(
            f"{ip:<17}"
            f"{mac:<20}"
            f"{hostname:<35}"
            f"{vendor:<25}"
            f"{role}"
        )

    return (
        local_count,
        gateway_count,
        device_count,
    )


# ============================================================
# JSON OUTPUT
# ============================================================

def write_json(
    data,
    filename="netwatch_scan.json",
):
    """
    Save scan results as JSON.
    """

    with open(
        filename,
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            data,
            file,
            indent=4,
        )


# ============================================================
# CSV OUTPUT
# ============================================================

def write_csv(
    data,
    filename="netwatch_scan.csv",
):
    """
    Save scan results as CSV.
    """

    devices = data["devices"]

    with open(
        filename,
        "w",
        newline="",
        encoding="utf-8",
    ) as file:

        fieldnames = [
            "ip",
            "mac",
            "hostname",
            "vendor",
            "role",
        ]

        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames,
        )

        writer.writeheader()

        for device in devices:
            writer.writerow(device)


# ============================================================
# SCAN COMMAND
# ============================================================

def scan_command(output_format=None):
    """
    Discover devices on the local network.

    Supported output formats:

        None
        json
        csv
    """

    try:

        (
            local_ip,
            network,
            interface,
            gateway,
        ) = get_network_info()

        # ----------------------------------------------------
        # NETWORK INFORMATION
        # ----------------------------------------------------

        print("[+] Network Information")
        print()

        print(
            f"    Interface : {interface}"
        )

        print(
            f"    Local IP  : {local_ip}"
        )

        print(
            f"    Network   : {network}"
        )

        print(
            f"    Gateway   : "
            f"{gateway if gateway else 'Unknown'}"
        )

        print()

        # ----------------------------------------------------
        # SCAN
        # ----------------------------------------------------

        print("[*] Scanning network...")
        print()

        start_time = time.perf_counter()

        devices = scan_network(network)

        devices = enrich_devices(
            devices,
            gateway,
        )

        elapsed = (
            time.perf_counter()
            - start_time
        )

        # ----------------------------------------------------
        # PUBLIC IP INTELLIGENCE
        # ----------------------------------------------------

        print(
            "[*] Gathering public IP intelligence..."
        )

        public_ip_intelligence = (
            get_public_ip_intelligence()
        )

        print()

        # ----------------------------------------------------
        # NO DEVICES
        # ----------------------------------------------------

        if not devices:

            print(
                "[-] No devices discovered."
            )

            print(
                f"[*] Scan completed in "
                f"{elapsed:.2f} seconds."
            )

            print()

            print_ip_intelligence(
                public_ip_intelligence
            )

            return False

        # ----------------------------------------------------
        # BUILD STRUCTURED DATA
        # ----------------------------------------------------

        scan_data = build_scan_data(
            local_ip,
            network,
            interface,
            gateway,
            devices,
            elapsed,
            public_ip_intelligence,
        )

        # ----------------------------------------------------
        # JSON OUTPUT
        # ----------------------------------------------------

        if output_format == "json":

            filename = "netwatch_scan.json"

            write_json(
                scan_data,
                filename,
            )

            print(
                f"[+] JSON report saved: "
                f"{filename}"
            )

            print(
                f"[+] {len(devices)} device"
                f"{'s' if len(devices) != 1 else ''} "
                f"discovered."
            )

            return True

        # ----------------------------------------------------
        # CSV OUTPUT
        # ----------------------------------------------------

        if output_format == "csv":

            filename = "netwatch_scan.csv"

            write_csv(
                scan_data,
                filename,
            )

            print(
                f"[+] CSV report saved: "
                f"{filename}"
            )

            print(
                f"[+] {len(devices)} device"
                f"{'s' if len(devices) != 1 else ''} "
                f"discovered."
            )

            return True

        # ----------------------------------------------------
        # NORMAL TABLE OUTPUT
        # ----------------------------------------------------

        (
            local_count,
            gateway_count,
            device_count,
        ) = print_device_table(
            local_ip,
            devices,
        )

        # ----------------------------------------------------
        # SCAN SUMMARY
        # ----------------------------------------------------

        print()
        print("=" * 110)

        print("[+] Scan Summary")
        print()

        print(
            f"    Devices discovered : "
            f"{len(devices)}"
        )

        print(
            f"    Local device       : "
            f"{local_count}"
        )

        print(
            f"    Gateway            : "
            f"{gateway_count}"
        )

        print(
            f"    Other devices      : "
            f"{device_count}"
        )

        print(
            f"    Scan time          : "
            f"{elapsed:.2f} seconds"
        )

        print("=" * 110)

        # ----------------------------------------------------
        # PUBLIC IP INTELLIGENCE
        # ----------------------------------------------------

        print()

        print_ip_intelligence(
            public_ip_intelligence
        )

        print("=" * 110)

        return True

    except KeyboardInterrupt:

        print()
        print("[!] Scan interrupted.")

        return False

    except Exception as error:

        print()
        print(
            f"[-] Scan failed: {error}"
        )

        return False


# ============================================================
# COMMAND LINE INTERFACE
# ============================================================

def main():

    parser = argparse.ArgumentParser(
        prog="netwatch",
        description=(
            "NetWatch - Local Network "
            "Intelligence Tool"
        ),
    )

    subparsers = parser.add_subparsers(
        dest="command"
    )

    # ========================================================
    # SCAN
    # ========================================================

    scan_parser = subparsers.add_parser(
        "scan",
        help="Discover devices on the local network",
    )

    scan_parser.add_argument(
        "--json",
        action="store_true",
        help="Save scan results as JSON",
    )

    scan_parser.add_argument(
        "--csv",
        action="store_true",
        help="Save scan results as CSV",
    )

    # ========================================================
    # INFO
    # ========================================================

    subparsers.add_parser(
        "info",
        help="Show active network information",
    )

    # ========================================================
    # INTERFACES
    # ========================================================

    subparsers.add_parser(
        "interfaces",
        help="List network interfaces",
    )

    # ========================================================
    # MONITOR
    # ========================================================

    subparsers.add_parser(
        "monitor",
        help="Monitor network devices in real time",
    )

    args = parser.parse_args()

    # ========================================================
    # NO COMMAND
    # ========================================================

    if not args.command:

        print_banner()
        parser.print_help()

        return

    # ========================================================
    # SCAN
    # ========================================================

    if args.command == "scan":

        print_banner()

        if args.json and args.csv:

            print(
                "[-] Error: "
                "--json and --csv cannot be used together."
            )

            sys.exit(1)

        output_format = None

        if args.json:
            output_format = "json"

        elif args.csv:
            output_format = "csv"

        success = scan_command(
            output_format
        )

        if not success:
            sys.exit(1)

    # ========================================================
    # INFO
    # ========================================================

    elif args.command == "info":

        print_banner()

        success = print_network_info()

        if not success:
            sys.exit(1)

    # ========================================================
    # INTERFACES
    # ========================================================

    elif args.command == "interfaces":

        print_banner()

        success = print_interfaces()

        if not success:
            sys.exit(1)

    # ========================================================
    # MONITOR
    # ========================================================

    elif args.command == "monitor":

        print_banner()

        try:
            monitor_network()

        except KeyboardInterrupt:

            print()
            print("[!] Monitoring stopped.")


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()

