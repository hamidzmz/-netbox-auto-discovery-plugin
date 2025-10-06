# NetBox Auto Discovery Plugin

Automatically discover and inventory network resources in NetBox via Network Range and Cisco Switch scans.

* **Author:** Hamid Zamani (hamidzamani445@gmail.com)
* **License:** Apache-2.0
* **Version:** 0.1.0

## Features

This NetBox plugin enables network administrators to automatically discover and inventory network resources:

### Scanner Types

1. **Network Range Scan**
   - Discover active IP addresses in a CIDR range (e.g., `192.168.1.0/24`)
   - Identify open ports and running services
   - Create/update `ipam.IPAddress` records with hostname information
   - Track discovered services (HTTP, SSH, SNMP, etc.)

2. **Cisco Switch Scan**
   - Connect via SSH or SNMP to Cisco switches
   - Extract device details (hostname, model, serial number, OS version)
   - Enumerate network interfaces and their configuration
   - Discover VLANs and their assignments
   - Create/update `dcim.Device`, `dcim.Interface`, and `ipam.VLAN` records

### Core Capabilities

- **Full NetBox Integration**: All discovered data stored in native NetBox models
- **Audit Trail**: Complete history of scan runs and discovered resources
- **Background Execution**: Long-running scans executed as background jobs
- **Credential Management**: Encrypted storage of SSH passwords and SNMP community strings
- **Automated Scanning**: Optional periodic scan scheduling
- **UI Management**: Create, configure, and execute scanners via NetBox UI

## Compatibility

| NetBox Version | Plugin Version |
|----------------|----------------|
|     4.0-4.9    |      0.1.0     |

## Installation

### Requirements

- NetBox 4.0 or later
- Python 3.10 or later
- `python-nmap` for network range scanning
- `netmiko` for SSH device connections
- `pysnmp` for SNMP operations

### Install via pip

```bash
pip install netbox-netbox-auto-discovery-plugin
```

### Install from Git (development)

```bash
pip install git+https://github.com/hamidzmz/netbox-netbox-auto-discovery-plugin
```

### NetBox Docker Installation

1. Add to `plugin_requirements.txt`:
   ```
   netbox-netbox-auto-discovery-plugin
   ```

2. Create or update `configuration/plugins.py`:
   ```python
   PLUGINS = [
       'netbox_netbox_auto_discovery_plugin',
   ]

   PLUGINS_CONFIG = {
       'netbox_netbox_auto_discovery_plugin': {
           'scan_timeout_seconds': 3600,  # Maximum scan duration
           'max_concurrent_scans': 5,     # Parallel scan limit
       },
   }
   ```

3. Rebuild the NetBox container:
   ```bash
   docker-compose build netbox
   docker-compose restart netbox netbox-worker
   ```

4. Run migrations:
   ```bash
   docker-compose exec netbox python manage.py migrate
   ```

## Usage

### Creating a Network Range Scanner

1. Navigate to **Plugins > Auto Discovery > Scanners**
2. Click **Add Scanner**
3. Configure:
   - **Name**: Descriptive name (e.g., "Office Network Scan")
   - **Scanner Type**: Network Range Scan
   - **CIDR Range**: Target network (e.g., `192.168.1.0/24`)
   - **Site**: Associated NetBox site (optional)
   - **Status**: Active

### Creating a Cisco Switch Scanner

1. Navigate to **Plugins > Auto Discovery > Scanners**
2. Click **Add Scanner**
3. Configure:
   - **Name**: Descriptive name (e.g., "Core Switch Scan")
   - **Scanner Type**: Cisco Switch Scan
   - **Target Hostname**: Switch IP or hostname
   - **Connection Protocol**: SSH or SNMP v2c/v3
   - **SSH/SNMP Credentials**: Authentication details
   - **Site**: Associated NetBox site (optional)

### Running a Scan

1. Navigate to the scanner detail page
2. Click **Run Scan** button (to be implemented in Phase 3)
3. Monitor progress in **Scan Runs** tab
4. View discovered resources in **Discovered Devices** or **Discovered IP Addresses**

### Viewing Scan History

- Navigate to **Plugins > Auto Discovery > Scan Runs**
- Filter by scanner, status, or date
- Click a run to see detailed logs and discovered resources

## Architecture

### Data Models

- **Scanner**: Configuration for a network or device scan
- **ScanRun**: Execution record with status, metrics, and logs
- **DiscoveredDevice**: Audit link between scan run and NetBox device
- **DiscoveredIPAddress**: Audit link between scan run and NetBox IP address

### Background Jobs

Scans execute as NetBox background jobs (`JobRunner`) for:
- Non-blocking UI operations
- Progress tracking and logging
- Error handling and retry logic

### Security

- SSH passwords stored using NetBox's encryption mechanisms
- SNMP community strings handled securely
- All scan activity logged with full audit trail

## Development

### Testing with Virtual Switches

Test Cisco switch scanning using virtual environments:

- **GNS3**: Import Cisco IOS images and create virtual topology
- **Containerlab**: Deploy Cisco CSR1000v or similar containers
- **EVE-NG**: Full-featured network emulation platform

Example GNS3 test setup:
```bash
# Install GNS3
# Import Cisco IOS image
# Create topology with management network
# Configure SSH/SNMP access
# Point scanner at virtual switch IP
```

### Running Tests

```bash
# Install test dependencies
pip install -e .[test]

# Run tests
pytest

# Code formatting
make format

# Linting
make lint
```

## Roadmap

- [x] Phase 1: Data models and migrations
- [ ] Phase 2: Background job implementation
- [ ] Phase 3: "Run Scan" action and UI enhancements
- [ ] Phase 4: REST API endpoints
- [ ] Phase 5: Search integration
- [ ] Phase 6: Docker integration examples
- [ ] Phase 7: Documentation and screenshots

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines.

## Credits

Developed by **Hamid Zamani** (hamidzamani445@gmail.com) as part of the NetBox plugin ecosystem.


Based on the NetBox plugin tutorial:

- [demo repository](https://github.com/netbox-community/netbox-plugin-demo)
- [tutorial](https://github.com/netbox-community/netbox-plugin-tutorial)

This package was created with [Cookiecutter](https://github.com/audreyr/cookiecutter) and the [`netbox-community/cookiecutter-netbox-plugin`](https://github.com/netbox-community/cookiecutter-netbox-plugin) project template.
