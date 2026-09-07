
import time
from datetime import datetime

from core.discovery import (
    enrich_devices,
    get_local_network,
    scan_network,
)


# ============================================================
# CONFIGURATION
# ============================================================

DEFAULT_INTERVAL = 5
OFFLINE_THRESHOLD = 3


# ============================================================
# HELPERS
# ============================================================

def timestamp():
    """
    Return the current time.
    """

    return datetime.now().strftime("%H:%M:%S")


def device_map(devices):
    """
    Convert a device list into a dictionary keyed by IP.
    """

    return {
        device["ip"]: device
        for device in devices
    }


def print_device(device):
    """
    Display device information.
    """

    print(f"  IP  : {device['ip']}")
    print(f"  MAC : {device['mac']}")

    hostname = device.get("hostname", "Unknown")

    if hostname != "Unknown":
        print(f"  Host: {hostname}")


# ============================================================
# INITIAL SCAN
# ============================================================

def initial_scan(network, gateway):
    """
    Perform the initial network scan.
    """

    devices = scan_network(network)

    return enrich_devices(
        devices,
        gateway,
    )


# ============================================================
# REALTIME MONITOR
# ============================================================

def monitor_network(interval=DEFAULT_INTERVAL):
    """
    Monitor the local network continuously.

    A device must miss OFFLINE_THRESHOLD consecutive scans
    before it is considered offline.
    """

    try:
        (
            local_ip,
            network,
            interface,
            gateway,
        ) = get_local_network()

    except Exception as error:
        print(
            f"[-] Unable to detect network: {error}"
        )
        return False

    print()
    print("[+] Network Monitor")
    print()
    print(f"    Interface : {interface}")
    print(f"    Local IP  : {local_ip}")
    print(f"    Network   : {network}")
    print(
        f"    Gateway   : "
        f"{gateway if gateway else 'Unknown'}"
    )
    print()
    print("[*] Starting realtime monitoring...")
    print(f"[*] Scan interval: {interval} seconds")
    print(
        f"[*] Offline threshold: "
        f"{OFFLINE_THRESHOLD} missed scans"
    )
    print("[*] Press Ctrl+C to stop.")
    print()

    # --------------------------------------------------------
    # INITIAL SCAN
    # --------------------------------------------------------

    try:
        devices = initial_scan(
            network,
            gateway,
        )

    except Exception as error:
        print(
            f"[-] Initial scan failed: {error}"
        )
        return False

    previous = device_map(devices)

    # Track consecutive missed scans.
    missed_scans = {
        ip: 0
        for ip in previous
    }

    print(
        f"[{timestamp()}] INITIALIZED"
    )

    print(
        f"  {len(previous)} device"
        f"{'s' if len(previous) != 1 else ''} online"
    )

    print()

    # --------------------------------------------------------
    # MONITORING LOOP
    # --------------------------------------------------------

    while True:

        time.sleep(interval)

        try:
            devices = scan_network(network)

            devices = enrich_devices(
                devices,
                gateway,
            )

            current = device_map(devices)

        except KeyboardInterrupt:
            raise

        except Exception as error:
            print(
                f"[{timestamp()}] SCAN ERROR"
            )
            print(f"  {error}")
            print()
            continue

        # ====================================================
        # NEW DEVICES
        # ====================================================

        new_ips = (
            set(current)
            - set(previous)
        )

        for ip in sorted(new_ips):

            device = current[ip]

            print(
                f"[{timestamp()}] NEW DEVICE"
            )

            print_device(device)
            print()

            missed_scans[ip] = 0

        # ====================================================
        # DEVICES THAT RESPONDED
        # ====================================================

        for ip in current:

            # Device responded again.
            missed_scans[ip] = 0

            # If it was previously missing, it has returned.
            if ip in previous and ip not in current:
                print(
                    f"[{timestamp()}] DEVICE ONLINE"
                )

                print_device(current[ip])
                print()

        # ====================================================
        # DEVICES THAT DID NOT RESPOND
        # ====================================================

        missing_ips = (
            set(previous)
            - set(current)
        )

        for ip in sorted(missing_ips):

            missed_scans[ip] = (
                missed_scans.get(ip, 0) + 1
            )

            device = previous[ip]

            # -----------------------------------------------
            # FIRST MISSED SCAN
            # -----------------------------------------------

            if missed_scans[ip] == 1:

                print(
                    f"[{timestamp()}] "
                    f"POSSIBLY OFFLINE"
                )

                print(
                    f"  IP  : {device['ip']}"
                )

                print(
                    f"  MAC : {device['mac']}"
                )

                print(
                    "  Waiting for confirmation..."
                )

                print()

            # -----------------------------------------------
            # CONFIRMED OFFLINE
            # -----------------------------------------------

            elif (
                missed_scans[ip]
                == OFFLINE_THRESHOLD
            ):

                print(
                    f"[{timestamp()}] "
                    f"DEVICE OFFLINE"
                )

                print_device(device)

                print()

        # ====================================================
        # ONLINE COUNT
        # ====================================================

        confirmed_offline = {
            ip
            for ip, misses in missed_scans.items()
            if misses >= OFFLINE_THRESHOLD
        }

        online_count = len(current)

        # Only show normal CHECK when there are no changes.
        if not new_ips and not missing_ips:

            print(
                f"[{timestamp()}] CHECK"
            )

            print(
                f"  {online_count} device"
                f"{'s' if online_count != 1 else ''} online"
            )

            print()

        # ====================================================
        # UPDATE STATE
        # ====================================================

        # Keep devices that are currently visible.
        previous = current

        # Keep missed-device information alive so the monitor
        # can track consecutive failed scans.
        for ip in list(missed_scans):

            if (
                ip not in previous
                and missed_scans[ip]
                < OFFLINE_THRESHOLD
            ):
                continue

            if (
                ip not in previous
                and missed_scans[ip]
                >= OFFLINE_THRESHOLD
            ):
                del missed_scans[ip]

