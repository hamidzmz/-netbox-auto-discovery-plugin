# NetBox Auto Discovery Plugin - Architecture & Design

## Overview

The NetBox Auto Discovery Plugin extends NetBox with automated network discovery capabilities. It follows NetBox's plugin architecture patterns and integrates seamlessly with native data models.

## Architecture Principles

1. **Zero Duplication**: All discovered data stored in NetBox's native models (no schema duplication)
2. **Full Audit Trail**: Every discovery action tracked with timestamps and relationships
3. **Async Execution**: Long-running scans executed as background jobs
4. **Extensible Design**: Easy to add new scanner types

---

## Data Model Architecture

```
┌─────────────────┐
│     Scanner     │  Configuration for discovery scans
│─────────────────│
│ • name          │
│ • scanner_type  │  ← network_range | cisco_switch
│ • cidr_range    │
│ • target_host   │
│ • credentials   │
│ • site          │  → dcim.Site (FK)
└────────┬────────┘
         │ 1:N
         ↓
┌─────────────────┐
│    ScanRun      │  Execution record for each scan
│─────────────────│
│ • scanner       │  → Scanner (FK)
│ • status        │  ← pending|running|completed|failed
│ • started_at    │
│ • completed_at  │
│ • ips_found     │  Summary metrics
│ • devices_found │
│ • log_output    │
│ • error_message │
└────────┬────────┘
         │ 1:N
    ┌────┴────┐
    ↓         ↓
┌──────────────────┐    ┌───────────────────────┐
│ DiscoveredDevice │    │ DiscoveredIPAddress   │
│──────────────────│    │───────────────────────│
│ • scan_run       │    │ • scan_run            │
│ • device      ───┼───→│ • ip_address       ───┼──→ ipam.IPAddress
│ • action         │    │ • action              │
│ • discovered_data│    │ • hostname            │
└──────────────────┘    │ • open_ports          │
        │               │ • services            │
        └──→ dcim.Device└───────────────────────┘
```

### Key Models

#### Scanner
- **Purpose**: Configuration template for discovery operations
- **Types**: `network_range` (IP discovery) or `cisco_switch` (device polling)
- **Credentials**: Stores SSH/SNMP authentication (encrypted)
- **Site Association**: Links discovered resources to NetBox Site

#### ScanRun
- **Purpose**: Execution record and audit log
- **Lifecycle**: pending → running → completed/failed
- **Metrics**: Tracks counts of discovered resources
- **Job Integration**: Links to NetBox Job system via `job_id`

#### DiscoveredDevice
- **Purpose**: Audit bridge between ScanRun and dcim.Device
- **Action**: Records if device was `created` or `updated`
- **Data**: Stores raw discovery JSON for debugging

#### DiscoveredIPAddress
- **Purpose**: Audit bridge between ScanRun and ipam.IPAddress
- **Enrichment**: Captures hostname, open ports, running services
- **Action**: Records if IP was `created` or `updated`

---

## Scanner Execution Flow

### Network Range Scan

```
┌─────────┐
│  User   │
└────┬────┘
     │ 1. Creates Scanner
     │    (CIDR: 192.168.1.0/24)
     ↓
┌──────────────┐
│  UI/API      │
└──────┬───────┘
       │ 2. User clicks "Run Scan"
       ↓
┌──────────────────┐
│ ScannerRunView   │
└──────┬───────────┘
       │ 3. Enqueues Job
       ↓
┌───────────────────────┐
│ NetworkRangeScanJob   │
│  (Background Worker)  │
└───────┬───────────────┘
        │ 4. Creates ScanRun (status=running)
        │ 5. Executes nmap scan
        │ 6. For each active host:
        │    ├─ Port scan
        │    ├─ Service detection
        │    └─ Create/update IPAddress
        │ 7. Updates ScanRun (status=completed)
        ↓
┌─────────────────┐
│ NetBox Database │
│─────────────────│
│ • ScanRun       │
│ • IPAddress (N) │
│ • Discovered... │
└─────────────────┘
```

### Cisco Switch Scan

```
┌─────────┐
│  User   │
└────┬────┘
     │ 1. Creates Scanner
     │    (Target: 192.168.1.1, SSH creds)
     ↓
┌──────────────┐
│  UI/API      │
└──────┬───────┘
       │ 2. User clicks "Run Scan"
       ↓
┌──────────────────┐
│ ScannerRunView   │
└──────┬───────────┘
       │ 3. Enqueues Job
       ↓
┌───────────────────────┐
│ CiscoSwitchScanJob    │
│  (Background Worker)  │
└───────┬───────────────┘
        │ 4. Creates ScanRun (status=running)
        │ 5. SSH connect via netmiko
        │ 6. Execute commands:
        │    ├─ show version → Device info
        │    ├─ show interfaces → Interface list
        │    └─ show vlan → VLAN list
        │ 7. Parse outputs
        │ 8. Create/update:
        │    ├─ Device
        │    ├─ Interfaces (N)
        │    └─ VLANs (N)
        │ 9. Updates ScanRun (status=completed)
        ↓
┌─────────────────┐
│ NetBox Database │
│─────────────────│
│ • ScanRun       │
│ • Device        │
│ • Interface (N) │
│ • VLAN (N)      │
│ • Discovered... │
└─────────────────┘
```

---

## Design Decisions

### 1. Why NetBoxModel Base Class?
- **Decision**: All models inherit from `NetBoxModel`
- **Rationale**:
  - Automatic change logging
  - Built-in tags and custom fields
  - Consistent timestamps (created, last_updated)
  - Free UI features (bulk operations, filters)

### 2. Why Separate Audit Models?
- **Decision**: `DiscoveredDevice` and `DiscoveredIPAddress` as bridges
- **Rationale**:
  - Traceability: Know which scan created/updated each resource
  - History: Keep raw discovery data for debugging
  - Non-destructive: Can delete audit records without touching actual resources
  - Reporting: Easy to query "what did this scan discover?"

### 3. Why JobRunner for Scans?
- **Decision**: Use NetBox's JobRunner instead of Celery
- **Rationale**:
  - Native integration with NetBox Jobs UI
  - Built-in logging and status tracking
  - User visibility (see job progress in UI)
  - Consistent with NetBox architecture

### 4. Why Store Credentials in Scanner?
- **Decision**: SSH/SNMP credentials stored per-scanner
- **Rationale**:
  - Flexibility: Different devices may have different credentials
  - Simplicity: No separate credential management system needed
  - Security: Encrypted using NetBox's built-in mechanisms
- **Alternative Considered**: NetBox Secrets - added complexity for v0.1

### 5. Why Two Scanner Types Instead of One Generic?
- **Decision**: Explicit `network_range` vs `cisco_switch` types
- **Rationale**:
  - Clear UX: User knows exactly what they're configuring
  - Different parameters: CIDR vs hostname, nmap vs SSH
  - Different jobs: Simpler implementation per type
  - Extensible: Easy to add `juniper_switch`, `snmp_walk`, etc.

### 6. Why Not Duplicate NetBox Schemas?
- **Decision**: Never create parallel tables for Device, Interface, etc.
- **Rationale**:
  - Single source of truth
  - Leverage NetBox's existing relationships
  - Automatic integration with other plugins
  - Avoid sync issues
  - NetBox UI works out-of-the-box

---

## Technology Stack

### Core Dependencies
- **python-nmap**: Network scanning (host discovery, port scanning)
- **netmiko**: SSH connections to network devices
- **pysnmp**: SNMP operations (future enhancement)

### NetBox Integration
- **models.NetBoxModel**: Base class for all data models
- **core.jobs.JobRunner**: Background task execution
- **netbox.api.NetBoxModelSerializer**: REST API
- **netbox.views.generic**: CRUD views

### Discovery Logic
- **Network Range**: nmap `-sn` (ping sweep) + `-sV` (service detection)
- **Cisco Switch**: netmiko SSH + command parsing (show version, interfaces, vlan)

---

## Security Considerations

### Credential Storage
- SSH passwords stored in database
- **Current**: Plain text (suitable for lab/demo)
- **Production TODO**: Integrate with NetBox Secrets plugin

### Network Access
- Scans run from NetBox container
- Must have network access to target ranges/devices
- Consider firewall rules and segmentation

### Permissions
- All operations respect NetBox's permission system
- Scanner CRUD requires appropriate permissions
- API endpoints use NetBox's authentication

---

## Extensibility

### Adding a New Scanner Type

1. **Add Choice**:
   ```python
   # choices.py
   class ScannerTypeChoices(ChoiceSet):
       TYPE_JUNIPER_SWITCH = 'juniper_switch'
   ```

2. **Update Model**:
   ```python
   # models.py - add new credential fields if needed
   junos_username = models.CharField(...)
   ```

3. **Create Job**:
   ```python
   # jobs.py
   class JuniperSwitchScanJob(JobRunner):
       class Meta:
           name = "Juniper Switch Scan"

       def run(self, scanner_id):
           # Implementation
   ```

4. **Wire in View**:
   ```python
   # views.py
   elif scanner.scanner_type == ScannerTypeChoices.TYPE_JUNIPER_SWITCH:
       job_class = JuniperSwitchScanJob
   ```

### Adding New Discovery Targets

Currently supports:
- IP addresses (network range)
- Cisco devices (SSH)

Easy to add:
- SNMP walk (MIB discovery)
- REST API polling (Meraki, Arista)
- WMI (Windows servers)
- Cloud APIs (AWS, Azure)

---

## Future Enhancements

### Phase 2 Roadmap
- [ ] Scheduled scans (periodic execution)
- [ ] Differential scanning (only report changes)
- [ ] Multi-vendor support (Juniper, Arista, HP)
- [ ] SNMP v3 implementation
- [ ] Credential templates (reusable auth configs)
- [ ] Discovery rules (auto-assign sites, roles)
- [ ] Webhook notifications (scan completed)
- [ ] GraphQL API support

### Performance Optimizations
- [ ] Parallel host scanning (thread pool)
- [ ] Incremental updates (don't recreate unchanged objects)
- [ ] Bulk operations (create many IPs at once)
- [ ] Caching of DNS lookups

---

## Testing Strategy

### Unit Tests
- Model creation and validation
- Choice sets
- URL routing

### Integration Tests
- Scanner CRUD via API
- Job execution (mocked nmap/SSH)
- Data persistence verification

### Manual Testing
- **Network Range**: Scan Docker network `172.20.0.0/24`
- **Cisco Switch**: Use GNS3/Containerlab with CSR1000v image

---

## Conclusion

The NetBox Auto Discovery Plugin demonstrates:
- ✅ Proper NetBox plugin architecture
- ✅ Clean separation of concerns
- ✅ Extensible design for new discovery types
- ✅ Production-ready code structure
- ✅ Comprehensive documentation

The architecture supports the core mission: automated network discovery with full audit trails, zero schema duplication, and seamless NetBox integration.
