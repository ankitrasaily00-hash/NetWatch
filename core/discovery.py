import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

import psutil
from scapy.all import ARP, Ether, srp
from scapy.config import conf


# ============================================================
# NETWORK DETECTION
# ============================================================

def get_default_gateway():
    """
    Detect the default IPv4 gateway using Scapy's routing table.

    Returns:
        str | None: Gateway IPv4 address.
    """

    try:
        route = conf.route.route("0.0.0.0")

        if route and len(route) >= 3:
            gateway = route[2]

            if gateway and gateway != "0.0.0.0":
                return gateway

    except Exception:
        pass

    return None


def get_default_interface():
    """
    Detect the interface used by the default IPv4 route.

    Returns:
        str | None: Interface name.
    """

    try:
        route = conf.route.route("0.0.0.0")

        if route and len(route) >= 4:
            return route[3]

    except Exception:
        pass

    return None


def is_virtual_or_ignored_ip(ip):
    """
    Ignore loopback and common VMware networks.
    """

    ignored_prefixes = (
        "127.",   
        "192.168.75.",
    )

    return ip.startswith(ignored_prefixes)


def get_local_network():
    """
    Detect the active LAN interface.

    Returns:
        tuple:
            local_ip
            network
            interface
            gateway
    """

    interfaces = psutil.net_if_stats()
    addresses = psutil.net_if_addrs()

    gateway = get_default_gateway()
    default_interface = get_default_interface()

    interface_order = []

    if default_interface:
        interface_order.append(default_interface)

    for interface in interfaces:

        if interface not in interface_order:
            interface_order.append(interface)

    for interface in interface_order:

        stats = interfaces.get(interface)

        if not stats:
            continue

        if not stats.isup:
            continue

        for address in addresses.get(interface, []):

            if address.family != socket.AF_INET:
                continue

            local_ip = address.address
            netmask = address.netmask

            if not local_ip:
                continue

            if not netmask:
                continue

            if is_virtual_or_ignored_ip(local_ip):
                continue

            try:
                network = ipaddress.ip_network(
                    f"{local_ip}/{netmask}",
                    strict=False,
                )

            except ValueError:
                continue

            return (
                local_ip,
                str(network),
                interface,
                gateway,
            )

    raise RuntimeError(
        "No active network interface found."
    )


# ============================================================
# ARP DISCOVERY
# ============================================================

def scan_network(network):
    """
    Discover devices on the local IPv4 network using ARP.

    Returns:
        list[dict]
    """

    packet = (
        Ether(dst="ff:ff:ff:ff:ff:ff")
        / ARP(pdst=network)
    )

    answered, _ = srp(
        packet,
        timeout=3,
        verbose=False,
    )

    devices = []

    for _, response in answered:

        devices.append(
            {
                "ip": response.psrc,
                "mac": response.hwsrc,
            }
        )

    devices.sort(
        key=lambda device: ipaddress.ip_address(
            device["ip"]
        )
    )

    return devices


# ============================================================
# HOSTNAME RESOLUTION
# ============================================================

def resolve_hostname(ip):
    """
    Attempt reverse DNS / hostname resolution.
    """

    try:
        hostname = socket.gethostbyaddr(ip)[0]

        if hostname:
            return hostname

    except (
        socket.herror,
        socket.gaierror,
        OSError,
    ):
        pass

    return "Unknown"


# ============================================================
# MAC ADDRESS UTILITIES
# ============================================================

def normalize_mac(mac):
    """
    Normalize a MAC address into XX:XX:XX:XX:XX:XX format.
    """

    if not mac:
        return ""

    mac = mac.strip()

    mac = (
        mac.replace("-", ":")
        .replace(".", ":")
        .upper()
    )

    # Handle Cisco-style xxxx.xxxx.xxxx format.
    if len(mac) == 14 and mac.count(":") == 3:
        mac = mac.replace(":", "")

    if len(mac) == 12 and ":" not in mac:
        mac = ":".join(
            mac[i:i + 2]
            for i in range(0, 12, 2)
        )

    return mac


def get_mac_oui(mac):
    """
    Extract the first three octets of a MAC address.

    Example:
        F8:5E:A0:A3:E4:D6
        -> F8:5E:A0
    """

    normalized = normalize_mac(mac)

    parts = normalized.split(":")

    if len(parts) < 3:
        return None

    return ":".join(parts[:3])


# ============================================================
# MAC VENDOR DATABASE
# ============================================================

MAC_VENDORS = {

    # --------------------------------------------------------
    # Current known devices
    # --------------------------------------------------------

    "04:75:F9": "TP-Link",
    "48:8F:4C": "ASUSTeK Computer",
    "F8:5E:A0": "Acer",

    # --------------------------------------------------------
    # Common vendors
    # --------------------------------------------------------

    "00:1A:2B": "Ayecom Technology",
    "00:1B:21": "Intel",
    "00:1C:42": "Parallels",
    "00:1E:67": "Intel",
    "00:22:68": "Dell",
    "00:24:E8": "Dell",
    "00:25:00": "Apple",
    "00:26:BB": "Apple",

    "3C:5A:B4": "Google",
    "3C:84:6A": "Apple",
    "40:CB:C0": "Apple",
    "44:65:0D": "Amazon",
    "50:32:37": "Raspberry Pi",
    "58:CB:52": "Apple",

    "60:45:BD": "Samsung",
    "70:3A:CB": "Samsung",
    "78:11:DC": "Samsung",
    "8C:85:90": "Samsung",
    "A8:6B:AD": "Samsung",

    "00:17:88": "Cisco",
    "00:1B:54": "Cisco",
    "00:1E:49": "Cisco",
    "00:26:0B": "Cisco",

    "00:0C:29": "VMware",
    "00:50:56": "VMware",
    "00:05:69": "VMware",

    "08:00:27": "Oracle VirtualBox",

    "00:E0:4C": "Realtek",
    "52:54:00": "QEMU",

    "00:15:5D": "Microsoft Hyper-V",

    # --------------------------------------------------------
    # Networking vendors
    # --------------------------------------------------------

    "00:0E:C6": "TP-Link",
    "10:FE:ED": "TP-Link",
    "14:EB:33": "TP-Link",

    "00:90:4C": "Cisco",
    "18:03:73": "Cisco",
    "2C:54:91": "Cisco",

    "00:1D:0F": "D-Link",
    "00:22:B0": "D-Link",
    "1C:7E:E5": "D-Link",

    "00:18:4D": "Netgear",
    "20:4E:7F": "Netgear",
    "A0:04:60": "Netgear",

    # --------------------------------------------------------
    # Laptop / PC vendors
    # --------------------------------------------------------

    "00:1E:C9": "Dell",
    "18:03:73": "Dell",

    "00:1F:3B": "HP",
    "3C:D9:2B": "HP",
    "98:FA:9B": "HP",

    "00:1B:24": "Lenovo",
    "28:D2:44": "Lenovo",
    "E8:6A:64": "Lenovo",

    "00:16:EA": "ASUSTeK Computer",
    "10:7B:44": "ASUSTeK Computer",
    "2C:56:DC": "ASUSTeK Computer",

    "00:1C:23": "Acer",
    "04:92:26": "Acer",

    # --------------------------------------------------------
    # Mobile vendors
    # --------------------------------------------------------

    "00:16:6F": "Apple",
    "00:17:F2": "Apple",
    "00:19:E3": "Apple",
    "00:1B:63": "Apple",

    "AC:37:43": "Apple",
    "B8:8D:12": "Apple",
    "DC:2B:2A": "Apple",
    "F0:18:98": "Apple",

    "00:07:AB": "Samsung",
    "00:12:47": "Samsung",
    "00:15:99": "Samsung",

    "10:2A:B3": "Huawei",
    "20:F4:78": "Huawei",
    "48:46:F1": "Huawei",

    "00:1A:11": "Google",
    "54:60:09": "Google",
    "F4:F5:D8": "Google",

    # --------------------------------------------------------
    # IoT / Smart devices
    # --------------------------------------------------------

    "18:B4:30": "Espressif",
    "24:0A:C4": "Espressif",
    "30:AE:A4": "Espressif",

    "B0:4A:39": "Amazon",
    "FC:65:DE": "Amazon",

    "B8:27:EB": "Raspberry Pi",
    "DC:A6:32": "Raspberry Pi",
    "E4:5F:01": "Raspberry Pi",
}


# ============================================================
# MAC VENDOR LOOKUP
# ============================================================

def lookup_mac_vendor(mac):
    """
    Identify the manufacturer from the MAC OUI.

    Returns:
        str: Vendor name or "Unknown".
    """

    oui = get_mac_oui(mac)

    if not oui:
        return "Unknown"

    return MAC_VENDORS.get(
        oui,
        "Unknown",
    )


# ============================================================
# DEVICE ENRICHMENT
# ============================================================

def enrich_devices(devices, gateway=None):
    """
    Add hostname, gateway role, and MAC vendor information.

    Hostname resolution is performed concurrently.
    """

    if not devices:
        return devices

    # --------------------------------------------------------
    # HOSTNAME RESOLUTION
    # --------------------------------------------------------

    max_workers = min(
        10,
        len(devices),
    )

    with ThreadPoolExecutor(
        max_workers=max_workers
    ) as executor:

        futures = {
            executor.submit(
                resolve_hostname,
                device["ip"],
            ): device
            for device in devices
        }

        for future in as_completed(futures):

            device = futures[future]

            try:
                device["hostname"] = future.result()

            except Exception:
                device["hostname"] = "Unknown"

    # --------------------------------------------------------
    # DEVICE INFORMATION
    # --------------------------------------------------------

    for device in devices:

        ip = device["ip"]
        mac = device["mac"]

        device["gateway"] = bool(
            gateway
            and ip == gateway
        )

        device["vendor"] = lookup_mac_vendor(
            mac
        )

    return devices