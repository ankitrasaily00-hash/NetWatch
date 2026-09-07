# NetWatch

**Local Network Intelligence Tool**

NetWatch is a Python-based command-line tool for discovering and monitoring devices on a local network. It combines ARP-based device discovery, hostname resolution, MAC vendor identification, network information, public IP intelligence, reporting, and real-time monitoring into a single CLI utility.

> **Status:** Active development

---

## Features

### Network Discovery

* Automatically detects the active network interface
* Identifies the local IPv4 address
* Determines the local network range
* Detects the default gateway
* Discovers devices using ARP
* Sorts discovered devices by IPv4 address

### Device Intelligence

* IP address detection
* MAC address detection
* Hostname resolution
* MAC address normalization
* OUI extraction
* MAC vendor identification
* Local device identification
* Gateway identification

### Public IP Intelligence

NetWatch can retrieve information about the network's public IP address, including:

* Public IP address
* Country
* Country code
* Region
* City
* Postal code
* Latitude
* Longitude
* Timezone
* ISP
* Organization
* ASN

> IP geolocation is approximate and should not be treated as precise physical location data.

### Real-Time Monitoring

The monitoring module tracks devices on the local network and can report events such as:

* New devices appearing
* Devices becoming unavailable
* Device status checks
* Consecutive missed scans
* Device recovery

### Reporting

Scan results can be exported as:

* JSON
* CSV

---

## CLI

```text
netwatch [-h] {scan,info,interfaces,monitor} ...
```

### Scan

Discover devices on the local network:

```bash
python netwatch.py scan
```

The scan displays information such as:

```text
IP ADDRESS       MAC ADDRESS         HOSTNAME                  VENDOR
------------------------------------------------------------------------------------------------
192.168.1.70     44:1c:a1:5d:ab:fd   Unknown                  Unknown
192.168.1.75     g8:5e:a0:a3:e4:d6   DESKTOP                 Acer
192.168.1.254    54:37:cb:95:84:e4   Unknown                  TP-Link
```

### JSON Output

Save scan results as JSON:

```bash
python netwatch.py scan --json
```

Output:

```text
netwatch_scan.json
```

### CSV Output

Save scan results as CSV:

```bash
python netwatch.py scan --csv
```

Output:

```text
netwatch_scan.csv
```

### Network Information

Display information about the active network:

```bash
python netwatch.py info
```

Example:

```text
Interface : Wi-Fi
Local IP  : 192.168.1.75
Network   : 192.168.1.0/24
Gateway   : 192.168.1.254
```

### Network Interfaces

List detected network interfaces:

```bash
python netwatch.py interfaces
```

### Real-Time Monitoring

Start network monitoring:

```bash
python netwatch.py monitor
```

Press:

```text
Ctrl+C
```

to stop monitoring.

---

## Installation

### Requirements

* Python 3.9+
* Scapy
* psutil
* Windows, Linux, or another platform supported by the dependencies

### Clone the Repository

```bash
git clone https://github.com/ankitrasaily00-hash/NetWatch.git
cd NetWatch
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

If a `requirements.txt` file is not present yet, install the current dependencies manually:

```bash
pip install scapy psutil
```

### Run NetWatch

```bash
python netwatch.py --help
```

---

## Project Structure

```text
NetWatch/
│
├── netwatch.py
│
├── core/
│   ├── discovery.py
│   ├── ipintel.py
│   └── monitor.py
│
├── requirements.txt
│
├── README.md
│
└── .gitignore
```

### Core Modules

| Module              | Purpose                                                         |
| ------------------- | --------------------------------------------------------------- |
| `netwatch.py`       | CLI entry point and command handling                            |
| `core/discovery.py` | Network detection, ARP discovery, hostname and MAC intelligence |
| `core/ipintel.py`   | Public IP and approximate IP intelligence                       |
| `core/monitor.py`   | Real-time network device monitoring                             |

---

## How It Works

NetWatch follows a simple discovery and enrichment pipeline:

```text
                    ┌─────────────────┐
                    │   NetWatch CLI  │
                    └────────┬────────┘
                             │
                             ▼
                  ┌─────────────────────┐
                  │ Network Detection   │
                  │ Interface / Gateway │
                  │ IP / Network        │
                  └──────────┬──────────┘
                             │
                             ▼
                  ┌─────────────────────┐
                  │   ARP Discovery     │
                  │                     │
                  │ IP + MAC Addresses  │
                  └──────────┬──────────┘
                             │
                             ▼
                  ┌─────────────────────┐
                  │ Device Enrichment   │
                  │                     │
                  │ Hostname            │
                  │ MAC Vendor          │
                  │ Gateway             │
                  │ Local Device        │
                  └──────────┬──────────┘
                             │
                             ▼
                  ┌─────────────────────┐
                  │     Reporting       │
                  │                     │
                  │ Terminal / JSON     │
                  │ CSV                 │
                  └─────────────────────┘
```

The monitoring functionality builds on the same discovery process to track changes in device availability over time.

---

## Security & Privacy

NetWatch is intended for **networks you own or are explicitly authorized to monitor**.

ARP discovery is performed against the local network detected by the tool. Public IP intelligence uses an external IP information service, so the public IP being queried is sent to that service.

Do not use NetWatch to monitor networks without authorization.

---

## Limitations

NetWatch is designed for local-network visibility rather than full network security assessment.

Some limitations include:

* ARP discovery primarily identifies IPv4 devices on the local Layer-2 network.
* Devices that do not respond to ARP may not appear.
* Hostname resolution depends on available DNS/local name-resolution services.
* MAC vendor identification depends on the available OUI/vendor database.
* IP geolocation is approximate.
* Public IP information describes the Internet-facing connection, not individual private LAN devices.
* Network visibility can vary depending on Wi-Fi isolation, VLANs, routing, firewalls, and network configuration.

---

## Roadmap

Planned improvements include:

* [ ] Expand MAC/OUI vendor database
* [ ] Improve device fingerprinting
* [ ] Add scan configuration options
* [ ] Improve monitoring events
* [ ] Add device history
* [ ] Add persistent monitoring data
* [ ] Improve terminal output
* [ ] Add richer JSON/CSV reporting
* [ ] Add configurable scan intervals
* [ ] Improve cross-platform compatibility
* [ ] Add additional network intelligence modules

---

## Development

NetWatch is being developed incrementally, with each version focusing on improving discovery, enrichment, monitoring, and reporting capabilities.

Contributions, ideas, and improvements are welcome.

---

## License

This project is currently under active development.

A formal open-source license can be added when the project reaches its intended release stage.

---

## Author

**Ankit Rasaily**

GitHub:

https://github.com/ankitrasaily00-hash
