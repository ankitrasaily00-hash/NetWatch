import ipaddress
import json
import urllib.request


# ============================================================
# IP INTELLIGENCE
# ============================================================

PUBLIC_IP_URL = "https://api.ipify.org?format=json"
GEO_API_URL = "https://ipwho.is/{ip}"


def is_private_ip(ip):
    """
    Check whether an IP address is private/local.
    """

    try:
        return ipaddress.ip_address(ip).is_private

    except ValueError:
        return False


def get_public_ip(timeout=5):
    """
    Detect the public IPv4 address of the current network.

    Returns:
        str | None
    """

    try:
        request = urllib.request.Request(
            PUBLIC_IP_URL,
            headers={
                "User-Agent": "NetWatch/1.0"
            },
        )

        with urllib.request.urlopen(
            request,
            timeout=timeout,
        ) as response:

            data = json.loads(
                response.read().decode("utf-8")
            )

        public_ip = data.get("ip")

        if public_ip:
            return public_ip

    except Exception:
        pass

    return None


def get_ip_geolocation(ip, timeout=5):
    """
    Retrieve approximate geolocation and network information
    for a public IPv4 address.

    Private/local IPs are not geolocated.

    Returns:
        dict
    """

    if not ip:
        return {
            "ip": None,
            "private": False,
            "available": False,
        }

    if is_private_ip(ip):
        return {
            "ip": ip,
            "private": True,
            "available": False,
            "message": "Private IP - no public geolocation.",
        }

    url = GEO_API_URL.format(ip=ip)

    try:
        request = urllib.request.Request(
            url,
            headers={
                "User-Agent": "NetWatch/1.0"
            },
        )

        with urllib.request.urlopen(
            request,
            timeout=timeout,
        ) as response:

            data = json.loads(
                response.read().decode("utf-8")
            )

        if not data.get("success", False):
            return {
                "ip": ip,
                "private": False,
                "available": False,
            }

        location = data.get("location") or {}
        connection = data.get("connection") or {}

        return {
            "ip": ip,
            "private": False,
            "available": True,

            "country": data.get("country"),
            "country_code": data.get("country_code"),
            "region": data.get("region"),
            "city": data.get("city"),
            "postal": data.get("postal"),

            "latitude": data.get("latitude"),
            "longitude": data.get("longitude"),

            "timezone": (
                location.get("timezone")
            ),

            "isp": connection.get("isp"),
            "organization": connection.get("org"),
            "asn": connection.get("asn"),
        }

    except Exception as error:
        return {
            "ip": ip,
            "private": False,
            "available": False,
            "error": str(error),
        }


def get_public_ip_intelligence(timeout=5):
    """
    Detect the current public IP and retrieve its
    approximate network/geolocation information.

    Returns:
        dict
    """

    public_ip = get_public_ip(timeout)

    if not public_ip:
        return {
            "available": False,
            "error": "Unable to determine public IP.",
        }

    intelligence = get_ip_geolocation(
        public_ip,
        timeout,
    )

    intelligence["public_ip"] = public_ip

    return intelligence