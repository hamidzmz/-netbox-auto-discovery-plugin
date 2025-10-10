# NetBox Auto Discovery Plugin - Demo Setup Guide

Complete configuration guide for demonstrating the NetBox Auto Discovery Plugin with a Cisco switch in GNS3.

---

## Table of Contents
1. [Overview](#overview)
2. [GNS3 Switch Configuration](#part-1-gns3-switch-configuration)
3. [Host System Configuration](#part-2-host-system-configuration-linux)
4. [Network Architecture](#part-3-network-architecture)
5. [NetBox Scanner Configuration](#part-4-netbox-scanner-configuration)
6. [Interview Demonstration Script](#part-5-interview-demonstration-script)
7. [Key Technical Points](#part-6-key-technical-points-for-interview)
8. [Troubleshooting](#part-7-troubleshooting-reference)

---

## Overview

This guide documents the complete configuration needed to demonstrate the NetBox Auto Discovery Plugin scanning a Cisco switch in GNS3.

**What You'll Demonstrate:**
- ✅ Automated network device discovery via SNMP and SSH
- ✅ Auto-population of devices, interfaces, and VLANs in NetBox
- ✅ Real-world integration with Cisco IOS devices
- ✅ Multi-protocol support (SNMP v2c/v3, SSH)
- ✅ Comprehensive validation and security features

---

## Part 1: GNS3 Switch Configuration

### Switch Details
- **Device**: Cisco IOU L2 Switch (i86bi-linux-l2-ipbasek9-15.1e)
- **Hostname**: IOU-TEST-SW01
- **Management IP**: 172.20.0.100/24
- **Console Port**: 5002 (telnet)

### Complete Switch Configuration

```cisco
!
! Basic Configuration
!
hostname IOU-TEST-SW01
!
ip domain-name netbox.local
!
! Create local admin user for SSH access
username admin privilege 15 secret cisco123
!
! Enable secret for privileged mode
enable secret cisco123
!
!
! Configure Management Interface
!
interface Ethernet0/0
 description MANAGEMENT_INTERFACE
 no switchport                          ! Make it Layer 3
 ip address 172.20.0.100 255.255.255.0  ! Assign management IP
 no shutdown
!
! Configure VLANs for demonstration
!
vlan 10
 name MANAGEMENT
!
vlan 20
 name SERVERS
!
vlan 30
 name WORKSTATIONS
!
vlan 40
 name GUEST
!
! Configure some switchports in different VLANs
!
interface Ethernet0/1
 description SERVER_PORT_1
 switchport mode access
 switchport access vlan 20
 duplex auto
!
interface Ethernet0/2
 description SERVER_PORT_2
 switchport mode access
 switchport access vlan 20
 duplex auto
!
interface Ethernet0/3
 description WORKSTATION_PORT_1
 switchport mode access
 switchport access vlan 30
 duplex auto
!
interface Ethernet1/0
 description WORKSTATION_PORT_2
 switchport mode access
 switchport access vlan 30
 duplex auto
!
interface Ethernet1/1
 description GUEST_PORT_1
 switchport mode access
 switchport access vlan 40
 duplex auto
!
! Configure Trunk Port (demonstrates trunk VLAN discovery)
!
interface Ethernet1/2
 description TRUNK_PORT_TO_DISTRIBUTION
 switchport trunk encapsulation dot1q
 switchport mode trunk
 switchport trunk allowed vlan 10,20,30,40
 duplex auto
!
! Default gateway for the switch
ip default-gateway 172.20.0.1
!
! Static route (optional, for routing outside the management network)
ip route 0.0.0.0 0.0.0.0 172.20.0.1
!
! SNMP Configuration - Critical for SNMP Scanning
!
snmp-server community public RO           ! Read-only community for SNMP v2c
snmp-server community private RW          ! Read-write community (not used by plugin)
snmp-server location "NetBox Lab - GNS3"
snmp-server contact "admin@netbox.local"
!
! SSH Configuration - Critical for SSH Scanning
!
! Generate RSA keys for SSH
crypto key generate rsa modulus 2048
!
! Configure VTY lines for SSH access
line vty 0 4
 login local              ! Use local user database
 transport input ssh      ! Only allow SSH (no telnet on VTY)
 exec-timeout 30 0
!
! Console line configuration
line con 0
 exec-timeout 0 0
 privilege level 15
 logging synchronous
!
end
!
! Save configuration
write memory
```

### Rationale for Switch Configuration

#### 1. Management Interface (Ethernet0/0)
- **Config**: `no switchport` + IP address 172.20.0.100/24
- **Why**: Makes it a Layer 3 routed port so the switch has an IP address reachable from the host
- **Purpose**: Allows NetBox to connect via SSH (port 22) and SNMP (port 161)

#### 2. Default Gateway
- **Config**: `ip default-gateway 172.20.0.1`
- **Why**: Points to the host's IP on gns3tap0 (172.20.0.1)
- **Purpose**: Not strictly necessary for this demo but good practice

#### 3. SNMP Configuration
- **Config**: `snmp-server community public RO`
- **Why**: Enables SNMP v2c with community string "public"
- **Purpose**: Allows NetBox to query device info, interfaces, and VLANs via SNMP
- **Security Note**: In production, use SNMPv3 or restrict by ACL

#### 4. SSH Configuration
- **Config**: `crypto key generate rsa` + `transport input ssh`
- **Why**: Enables SSH server on the switch
- **Purpose**: Allows NetBox to connect via SSH and run show commands
- **User**: `username admin secret cisco123` for authentication

#### 5. VLANs
- **Config**: VLANs 10, 20, 30, 40 with descriptive names
- **Why**: Demonstrates that NetBox can discover VLANs via SNMP
- **Purpose**: Shows real-world switch configuration

#### 6. Interface Assignments (Access Ports)
- **Config**: Assign ports to different VLANs with descriptions
  - Et0/1, Et0/2 → VLAN 20 (SERVERS)
  - Et0/3, Et1/0 → VLAN 30 (WORKSTATIONS)
  - Et1/1 → VLAN 40 (GUEST)
- **Why**: Demonstrates realistic switchport configuration
- **Purpose**: Shows that NetBox discovers all interfaces and their VLAN assignments

#### 7. Trunk Port Configuration (NEW!)
- **Config**: Ethernet1/2 as trunk carrying VLANs 10, 20, 30, 40
- **Why**: Demonstrates the plugin's ability to discover trunk ports and their allowed VLANs
- **Purpose**: Shows advanced VLAN-to-interface relationship mapping
- **Technical**: Sets interface mode to "Tagged" in NetBox and populates tagged_vlans many-to-many relationship
- **Result**: NetBox will show Et1/2 as a trunk port with 4 tagged VLANs

---

## Part 2: Host System Configuration (Linux)

### GNS3 TAP Interface Setup

#### Step 1: Verify GNS3 TAP Interface Exists

```bash
# Check if gns3tap0 exists
ip link show gns3tap0
```

**Expected Output:**
```
53: gns3tap0: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN
```

**Rationale**: GNS3 creates this TAP interface automatically when you add a Cloud node and bind it to gns3tap0.

---

#### Step 2: Bring Up the Interface

```bash
# Activate the interface
sudo ip link set gns3tap0 up
```

**Rationale**: 
- The interface starts in DOWN state
- Must be brought UP to pass traffic
- **Why**: TAP interfaces don't auto-activate like physical NICs

---

#### Step 3: Assign IP Address

```bash
# Assign IP 172.20.0.1/24 to match switch's network
sudo ip addr add 172.20.0.1/24 dev gns3tap0
```

**Rationale**:
- **IP 172.20.0.1**: Acts as the default gateway for the switch (172.20.0.100)
- **Subnet /24**: Matches the switch's subnet (172.20.0.0/24)
- **Why**: Puts your host on the same Layer 2 network as the switch management interface

---

#### Step 4: Verify Configuration

```bash
# Check the interface is up with correct IP
ip addr show gns3tap0

# Test connectivity to the switch
ping -c 3 172.20.0.100
```

**Expected Output:**
```
53: gns3tap0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 ...
    inet 172.20.0.1/24 scope global gns3tap0
```

```
PING 172.20.0.100 (172.20.0.100) 56(84) bytes of data.
64 bytes from 172.20.0.100: icmp_seq=1 ttl=255 time=2.34 ms
```

**Rationale**: Confirms Layer 3 connectivity between host and switch.

---

#### Step 5: Test SNMP Connectivity (Optional Verification)

```bash
# Query switch via SNMP to verify it's responding
snmpget -v2c -c public 172.20.0.100 1.3.6.1.2.1.1.5.0
```

**Expected Output:**
```
iso.3.6.1.2.1.1.5.0 = STRING: "IOU-TEST-SW01.netbox.local"
```

**Rationale**: 
- Verifies SNMP is working before trying with NetBox
- **OID 1.3.6.1.2.1.1.5.0**: sysName (device hostname)
- **Why**: Troubleshoots SNMP issues independently of NetBox

---

#### Step 6: Test SSH Connectivity (Optional Verification)

```bash
# Try SSH to the switch
ssh admin@172.20.0.100
# Password: cisco123
```

**Expected**: SSH login prompt, then switch CLI

**Rationale**: 
- Verifies SSH is working before trying with NetBox
- **Why**: Confirms credentials and legacy algorithm support

---

### Complete Setup Script (One Command)

Save this as `setup-gns3-tap.sh`:

```bash
#!/bin/bash
# Setup GNS3 TAP interface for NetBox integration

echo "Setting up gns3tap0 interface..."

# Bring interface up
sudo ip link set gns3tap0 up

# Assign IP address
sudo ip addr add 172.20.0.1/24 dev gns3tap0

# Verify
echo "Configuration complete!"
ip addr show gns3tap0 | grep -E "inet|state"

# Test connectivity
echo "Testing connectivity to switch..."
ping -c 3 172.20.0.100

echo "Setup complete. NetBox can now scan 172.20.0.100"
```

**Run with:**
```bash
chmod +x setup-gns3-tap.sh
./setup-gns3-tap.sh
```

---

## Part 3: Network Architecture

### Physical/Virtual Topology

```
┌─────────────────────────────────────┐
│     Your Linux Host System          │
│                                      │
│  ┌────────────────────────────┐    │
│  │  NetBox (Docker)           │    │
│  │  http://127.0.0.1:8000     │    │
│  │                             │    │
│  │  Auto Discovery Plugin      │    │
│  └──────────┬──────────────────┘    │
│             │                        │
│             │ Uses host networking   │
│             │                        │
│  ┌──────────▼──────────────────┐    │
│  │  gns3tap0 Interface         │    │
│  │  IP: 172.20.0.1/24          │    │
│  └──────────┬──────────────────┘    │
│             │                        │
│             │ TAP Interface          │
│             │ (Layer 2 Bridge)       │
│             │                        │
│  ┌──────────▼──────────────────┐    │
│  │  GNS3 Process               │    │
│  │  (Running IOU Switch)       │    │
│  │                              │    │
│  │  ┌────────────────────────┐ │    │
│  │  │ IOU-TEST-SW01          │ │    │
│  │  │ Eth0/0: 172.20.0.100/24│ │    │
│  │  │ SSH Port: 22           │ │    │
│  │  │ SNMP Port: 161         │ │    │
│  │  └────────────────────────┘ │    │
│  └─────────────────────────────┘    │
└─────────────────────────────────────┘
```

### Network Flow Explanation

#### 1. NetBox → Switch (SSH Scan)
```
NetBox Container → Host Network Stack → gns3tap0 (172.20.0.1) 
  → GNS3 TAP Bridge → IOU Switch (172.20.0.100:22)
```

#### 2. NetBox → Switch (SNMP Scan)
```
NetBox Container → Host Network Stack → gns3tap0 (172.20.0.1) 
  → GNS3 TAP Bridge → IOU Switch (172.20.0.100:161)
```

**Why This Works**:
- Docker's `host` networking mode: NetBox uses host's network stack directly
- TAP interface: Acts as virtual Layer 2 switch connecting host to GNS3
- IP addressing: Both on same subnet (172.20.0.0/24) = Layer 2 adjacent

---

## Part 4: NetBox Scanner Configuration

### Access NetBox

```
URL: http://127.0.0.1:8000
Username: admin
Password: admin
```

### Create Scanner in NetBox UI

**Navigate to**: Plugins → Auto Discovery → Scanners → Add

#### For SNMP v2c Scan:

| Field | Value | Rationale |
|-------|-------|-----------|
| **Name** | `GNS3 Switch Scanner` | Descriptive name |
| **Scanner Type** | `Cisco Switch Scan` | Type of device |
| **Status** | `Active` | Enable scanning |
| **Target Hostname** | `172.20.0.100` | Switch management IP |
| **Connection Protocol** | `SNMP v2c` | Protocol to use |
| **SNMP Community** | `public` | Matches switch config |
| **SNMP Port** | `161` | Standard SNMP port |
| **Site** | *(leave empty)* | Auto-creates "Auto Discovery" |

**Rationale**:
- SNMP discovers more info: interfaces, VLANs, full MIB data
- Faster than SSH (no command parsing needed)
- Read-only operation (safe)

#### For SSH Scan:

| Field | Value | Rationale |
|-------|-------|-----------|
| **Name** | `GNS3 Switch SSH Scanner` | Descriptive name |
| **Scanner Type** | `Cisco Switch Scan` | Type of device |
| **Status** | `Active` | Enable scanning |
| **Target Hostname** | `172.20.0.100` | Switch management IP |
| **Connection Protocol** | `SSH` | Protocol to use |
| **SSH Username** | `admin` | Matches switch user |
| **SSH Password** | `cisco123` | Matches switch password |
| **SSH Port** | `22` | Standard SSH port |
| **Site** | *(leave empty)* | Auto-creates "Auto Discovery" |

**Rationale**:
- SSH works on devices without SNMP
- Can run complex show commands
- Authenticated access (more secure than SNMPv2c)

---

## Part 5: Interview Demonstration Script

### Scenario: "Demonstrate NetBox Auto Discovery"

#### 1. Show the GNS3 Topology

```bash
# Show GNS3 is running
ps aux | grep gns3

# Show the switch console
telnet localhost 5002
# (Shows switch prompt IOU-TEST-SW01#)
```

**Say**: *"I have a Cisco IOS switch running in GNS3 at 172.20.0.100"*

---

#### 2. Show Network Connectivity

```bash
# Show TAP interface configuration
ip addr show gns3tap0

# Test reachability
ping -c 3 172.20.0.100
```

**Say**: *"I configured a TAP interface bridging my host (172.20.0.1) to the GNS3 switch (172.20.0.100)"*

---

#### 3. Verify SNMP is Working

```bash
# Query device via SNMP
snmpget -v2c -c public 172.20.0.100 1.3.6.1.2.1.1.5.0

# Walk interface table
snmpwalk -v2c -c public 172.20.0.100 1.3.6.1.2.1.2.2.1.2 | head -5
```

**Say**: *"The switch has SNMP enabled with community 'public', allowing programmatic discovery"*

---

#### 4. Show NetBox Scanner Configuration

**In Browser**: Navigate to NetBox → Plugins → Auto Discovery → Scanners

**Say**: *"I've configured a scanner targeting 172.20.0.100 using SNMP v2c protocol"*

---

#### 5. Run the Scan

**Click**: "Run Scan" button on the scanner

**Say**: *"Let me trigger the auto-discovery scan..."*

---

#### 6. Show Results

**Point out**:
- Device discovered: IOU-TEST-SW01
- 19 interfaces created via SNMP (or 16 via SSH)
- 9 VLANs discovered (MANAGEMENT, SERVERS, WORKSTATIONS, GUEST, etc.)
- **9 VLAN assignments created** (5 access ports + 4 trunk VLANs) ← **NEW!**
- Scan completed in < 1-2 seconds

**Say**: *"NetBox automatically discovered the device, all its interfaces, VLANs, and their relationships using SSH"*

---

#### 7. Navigate to Discovered Resources

**Show in NetBox**:

1. **Devices → Devices → IOU-TEST-SW01**
   - Device model, manufacturer (Cisco)
   - Site: "Auto Discovery" (auto-created)
   - All metadata

2. **Click on device → Interfaces tab**
   - Show all 19 interfaces (or 16 if SSH)
   - Ethernet0/0, 0/1, 0/2... 
   - Vlan1, Vlan10, Null0

3. **IPAM → VLANs**
   - VLAN 1 (default)
   - VLAN 10 (MANAGEMENT)
   - VLAN 20 (SERVERS)
   - VLAN 30 (WORKSTATIONS)
   - VLAN 40 (GUEST)

4. **Click on Ethernet0/1 (Access Port)**
   - Mode: `Access`
   - Untagged VLAN: `20 (SERVERS)`
   - **Say**: *"The plugin automatically detected this is an access port and assigned it to VLAN 20"*

5. **Click on Ethernet1/2 (Trunk Port) ← NEW!**
   - Mode: `Tagged` (Trunk)
   - Tagged VLANs: `10 (MANAGEMENT), 20 (SERVERS), 30 (WORKSTATIONS), 40 (GUEST)`
   - **Say**: *"This is a trunk port. The plugin parsed the allowed VLAN list and automatically populated the tagged VLANs many-to-many relationship"*

**Say**: *"All this data - devices, interfaces, VLANs, AND their relationships - was automatically discovered and populated without manual entry"*

---

#### 8. Demonstrate Validation (Bonus)

**Create a new scanner with invalid config**:
- Try SNMP v3 without auth protocol → Shows validation error
- Try invalid protocol value (e.g., "XYZ") → Shows "Must be MD5, SHA, or SHA1"

**Say**: *"The plugin includes comprehensive validation to prevent misconfigurations"*

---

## Part 6: Key Technical Points for Interview

### Architecture Highlights

#### 1. Plugin Architecture
- Extends NetBox with custom models (Scanner, ScanRun, DiscoveredDevice)
- Integrates with NetBox's job system for background execution
- Uses Django ORM for data persistence

#### 2. Multi-Protocol Support
- **SNMP v2c**: Community-based, fast, comprehensive data
- **SNMP v3**: Secure with auth/priv protocols (MD5/SHA, DES/AES)
- **SSH**: Netmiko-based, works with legacy devices

#### 3. Validation Strategy
- **3-layer defense**: Models (Django clean()), Forms (UI), API Serializers (REST)
- **Field-level validation**: CIDR format, protocol values, credential requirements
- **Cross-field validation**: Privacy key requires privacy protocol

#### 4. Security Features
- Password fields are `write_only=True` in API (never returned in GET)
- Credentials stored securely in database
- SSH uses paramiko with legacy algorithm support

#### 5. Discovery Capabilities
- **Devices**: Hostname, model, serial, OS version
- **Interfaces**: Name, type, status
- **VLANs**: ID, name, site assignment
- **VLAN-to-Interface Mapping (NEW!)**: 
  - Access ports: Sets `untagged_vlan` and mode='access'
  - Trunk ports: Populates `tagged_vlans` many-to-many and mode='tagged'
  - Parses `show interfaces switchport` output via SSH
  - Handles comma-separated VLAN lists and ranges
- **Atomic transactions**: All-or-nothing updates

#### 6. Pysnmp Compatibility
- Started with pysnmp 4.4.12 (Python 3.12 incompatible)
- Switched to pysnmp 6.1.4 (official, maintained)
- Used `bulkCmd` for sync API (returns list of lists)
- Raw OIDs (no MIB files needed)

### Discovery Method Comparison

| Feature | SSH Scan | SNMP Scan |
|---------|----------|-----------|
| **Speed** | Slower (~1-2s) | Faster (<1s) |
| **Data Richness** | Limited | Comprehensive |
| **Interfaces** | 16 (show interfaces status) | 19 (full MIB walk) |
| **VLANs** | Limited parsing | Full VLAN table |
| **VLAN Assignments** | ✅ Via `show interfaces switchport` | ⚠️ Requires Cisco MIBs (IOU limited) |
| **Authentication** | Username/Password | Community/USM |
| **Security** | Encrypted (SSH) | Plain (v2c) / Encrypted (v3) |
| **Legacy Support** | Excellent (IOS 12.4+) | Excellent (all SNMP versions) |

### Code Structure

```
netbox-netbox-auto-discovery-plugin/
├── models.py              # Scanner, ScanRun, DiscoveredDevice models
├── forms.py               # UI forms with validation
├── views.py               # Django views for UI
├── jobs.py                # Core scanning logic (SSH & SNMP)
├── api/
│   └── serializers.py     # REST API with validation
├── tables.py              # NetBox table definitions
├── navigation.py          # UI menu integration
└── templates/             # HTML templates
```

---

## Part 7: Troubleshooting Reference

### Common Issues and Solutions

#### Issue 1: "No route to host"

```bash
# Solution: Verify TAP interface is UP and has IP
sudo ip link set gns3tap0 up
sudo ip addr add 172.20.0.1/24 dev gns3tap0
ping 172.20.0.100
```

**Cause**: TAP interface not configured or switch not running

---

#### Issue 2: "SNMP timeout"

```bash
# Solution: Verify SNMP is configured on switch
snmpget -v2c -c public 172.20.0.100 1.3.6.1.2.1.1.5.0

# If fails, check switch config
telnet localhost 5002
# On switch:
show run | include snmp
```

**Cause**: SNMP not enabled or wrong community string

---

#### Issue 3: "SSH connection refused"

```bash
# Solution: Verify SSH is enabled on switch
ssh admin@172.20.0.100

# If fails, check switch
telnet localhost 5002
# On switch:
show ip ssh
crypto key generate rsa modulus 2048
```

**Cause**: SSH not enabled or RSA keys missing

---

#### Issue 4: "Site required" error

- **Cause**: Device creation requires site, but none provided
- **Solution**: ✅ Already fixed - auto-creates "Auto Discovery" site
- **Code**: Check `_create_or_update_device()` method in `jobs.py`

---

#### Issue 5: "ImportError: cannot import name 'getCmd'"

- **Cause**: pysnmp version incompatibility
- **Solution**: ✅ Already fixed - using pysnmp 6.1.4 with correct imports
- **Check**: `pyproject.toml` should have `pysnmp>=6.1.3,<6.2`

---

#### Issue 6: Docker container fails to start

```bash
# Check container logs
cd netbox-docker
docker compose logs netbox --tail 50

# Rebuild if needed
docker compose build --no-cache netbox
docker compose up -d
```

---

### Quick Verification Checklist

Before demonstration, verify:

- [ ] GNS3 switch is running (`ps aux | grep gns3`)
- [ ] TAP interface is UP (`ip link show gns3tap0`)
- [ ] TAP interface has IP (`ip addr show gns3tap0`)
- [ ] Switch is reachable (`ping 172.20.0.100`)
- [ ] SNMP works (`snmpget -v2c -c public 172.20.0.100 1.3.6.1.2.1.1.5.0`)
- [ ] SSH works (`ssh admin@172.20.0.100`)
- [ ] Switchport config verified (`ssh admin@172.20.0.100 "show interfaces switchport"` shows access + trunk ports)
- [ ] NetBox is accessible (`curl http://127.0.0.1:8000`)
- [ ] Docker containers healthy (`docker compose ps`)

---

## Summary

### What This Setup Demonstrates

1. ✅ Network virtualization with GNS3
2. ✅ TAP interface configuration for host-to-VM networking
3. ✅ Cisco IOS configuration for remote management (SSH + SNMP)
4. ✅ NetBox plugin development and integration
5. ✅ Multi-protocol device discovery (SSH and SNMP)
6. ✅ Data validation and security best practices
7. ✅ Real-world network automation workflow

### Interview Talking Points

- *"Implemented full-stack NetBox plugin with 3-layer validation"*
- *"Integrated SNMP v2c/v3 and SSH protocols for device discovery"*
- *"Discovers VLAN-to-interface relationships: access ports (untagged) and trunk ports (tagged)"*
- *"Parses complex CLI output (`show interfaces switchport`) with stateful logic"*
- *"Configured GNS3 lab environment to test against real Cisco IOS"*
- *"Resolved pysnmp 6.1 compatibility issues for Python 3.12"*
- *"Follows Django/NetBox best practices for security and data integrity"*
- *"Auto-creates default site when none specified for better UX"*
- *"Implements atomic transactions for data consistency"*
- *"Password fields are write-only in API for security"*
- *"Handles many-to-many relationships (trunk ports with multiple tagged VLANs)"*

### Expected Demo Results

**SNMP Scan:**
- ✅ 1 Device discovered (IOU-TEST-SW01)
- ✅ 19 Interfaces created
- ✅ 9 VLANs discovered
- ⚠️ 0 VLAN assignments (IOU doesn't support Cisco VLAN Membership MIBs)
- ✅ Duration: < 1 second

**SSH Scan (Recommended for Demo):**
- ✅ 1 Device discovered (IOU-TEST-SW01)
- ✅ 16 Interfaces created
- ✅ 5-9 VLANs discovered
- ✅ **9 VLAN assignments** (5 access ports + 4 trunk VLANs) ← **NEW!**
- ✅ Duration: ~1-2 seconds

**VLAN Assignment Details:**
- **Access Ports**: Et0/1, Et0/2 → VLAN 20 | Et0/3, Et1/0 → VLAN 30 | Et1/1 → VLAN 40
- **Trunk Port**: Et1/2 → VLANs 10, 20, 30, 40 (tagged)

---

## Additional Resources

### NetBox API Testing

```bash
# Get scanner list
curl -H "Authorization: Token YOUR_TOKEN" \
  http://127.0.0.1:8000/api/plugins/netbox-netbox-auto-discovery-plugin/scanners/

# Create scanner via API
curl -X POST -H "Authorization: Token YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "API Test Scanner",
    "scanner_type": "cisco_switch",
    "target_hostname": "172.20.0.100",
    "connection_protocol": "snmp_v2c",
    "snmp_community": "public"
  }' \
  http://127.0.0.1:8000/api/plugins/netbox-netbox-auto-discovery-plugin/scanners/
```

### GNS3 Project Location

```bash
# Find your GNS3 project
ls ~/GNS3/projects/

# View project configuration
cat ~/GNS3/projects/NetBox-Test/NetBox-Test.gns3
```

### Docker Commands Reference

```bash
# View logs
docker compose logs netbox -f

# Restart services
docker compose restart netbox netbox-worker

# Rebuild plugin
docker compose build --no-cache netbox
docker compose up -d

# Access Django shell
docker compose exec netbox python manage.py shell
```

---

**Good luck with your interview! 🚀**

For questions or issues, refer to the troubleshooting section or check the project documentation.
