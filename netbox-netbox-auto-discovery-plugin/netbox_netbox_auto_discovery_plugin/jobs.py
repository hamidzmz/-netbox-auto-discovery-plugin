import logging
from datetime import datetime, timezone
from typing import Any, Dict
import nmap
import paramiko
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException
try:
    from pysnmp.hlapi import (
        getCmd, bulkCmd, SnmpEngine, CommunityData, UsmUserData,
        ContextData, ObjectType, ObjectIdentity, UdpTransportTarget,
        usmHMACMD5AuthProtocol, usmHMACSHAAuthProtocol,
        usmDESPrivProtocol, usmAesCfb128Protocol
    )
    PYSNMP_AVAILABLE = True
except ImportError:
    PYSNMP_AVAILABLE = False
from core.jobs import JobRunner
from dcim.models import Device, DeviceType, DeviceRole, Manufacturer, Site, Interface
from ipam.models import IPAddress, VLAN
from django.db import transaction
from .models import Scanner, ScanRun, DiscoveredDevice, DiscoveredIPAddress
from .choices import ScanRunStatusChoices, ConnectionProtocolChoices
logger = logging.getLogger('netbox.plugins.auto_discovery')
class NetworkRangeScanJob(JobRunner):

    class Meta:
        name = "Network Range Scan"
    def run(self, scanner_id: int) -> Dict[str, Any]:

        scanner = Scanner.objects.get(pk=scanner_id)
        scan_run = ScanRun.objects.create(
            scanner=scanner,
            status=ScanRunStatusChoices.STATUS_RUNNING,
            started_at=datetime.now(timezone.utc)
        )
        log_lines = []
        try:
            log_lines.append(f"Starting network range scan for {scanner.cidr_range}")
            self.logger.info(f"Scanning range: {scanner.cidr_range}")
            nm = nmap.PortScanner()
            log_lines.append(f"Performing host discovery scan...")
            nm.scan(hosts=scanner.cidr_range, arguments='-sn -T4')
            ips_discovered = 0
            discovered_hosts = []
            for host in nm.all_hosts():
                hostname = ''
                if 'hostnames' in nm[host] and nm[host]['hostnames']:
                    hostname = nm[host]['hostnames'][0]['name']
                discovered_hosts.append((host, hostname))
            log_lines.append(f"Found {len(discovered_hosts)} host(s) in range")
            for host, hostname in discovered_hosts:
                log_lines.append(f"Found active host: {host}")
                self.logger.info(f"Processing host: {host}")
                if hostname:
                    log_lines.append(f"  Hostname: {hostname}")
                log_lines.append(f"  Scanning services on {host}...")
                nm.scan(hosts=host, arguments='-sV -p 22,23,80,443,161,8080')
                open_ports = []
                services = {}
                if host in nm.all_hosts() and 'tcp' in nm[host]:
                    for port, port_info in nm[host]['tcp'].items():
                        if port_info['state'] == 'open':
                            open_ports.append(port)
                            services[str(port)] = {
                                'name': port_info.get('name', 'unknown'),
                                'product': port_info.get('product', ''),
                                'version': port_info.get('version', ''),
                            }
                            log_lines.append(f"    Port {port}: {port_info.get('name', 'unknown')}")
                with transaction.atomic():
                    ip_address, created = IPAddress.objects.get_or_create(
                        address=f"{host}/32",
                        defaults={
                            'status': 'active',
                            'dns_name': hostname,
                            'description': f'Discovered by Auto Discovery scan on {scan_run.started_at.strftime("%Y-%m-%d %H:%M")}',
                        }
                    )
                    if not created:
                        ip_address.status = 'active'
                        if hostname:
                            ip_address.dns_name = hostname
                        ip_address.description = f'Last seen by Auto Discovery on {scan_run.started_at.strftime("%Y-%m-%d %H:%M")}'
                        ip_address.save()
                    if scanner.site:
                        ip_address.site = scanner.site
                        ip_address.save()
                    DiscoveredIPAddress.objects.create(
                        scan_run=scan_run,
                        ip_address=ip_address,
                        action='created' if created else 'updated',
                        hostname=hostname,
                        open_ports=open_ports if open_ports else None,
                        services=services if services else None,
                    )
                    ips_discovered += 1
                    log_lines.append(f"  {'Created' if created else 'Updated'} IP address record in NetBox")
            scan_run.status = ScanRunStatusChoices.STATUS_COMPLETED
            scan_run.completed_at = datetime.now(timezone.utc)
            scan_run.ips_discovered = ips_discovered
            scan_run.log_output = '\n'.join(log_lines)
            scan_run.save()
            self.logger.info(f"Scan completed. Discovered {ips_discovered} IPs")
            return {
                'success': True,
                'ips_discovered': ips_discovered,
                'scan_run_id': scan_run.pk,
            }
        except Exception as e:
            error_msg = f"Scan failed: {str(e)}"
            log_lines.append(f"ERROR: {error_msg}")
            self.logger.error(error_msg, exc_info=True)
            scan_run.status = ScanRunStatusChoices.STATUS_FAILED
            scan_run.completed_at = datetime.now(timezone.utc)
            scan_run.error_message = error_msg
            scan_run.log_output = '\n'.join(log_lines)
            scan_run.save()
            return {
                'success': False,
                'error': error_msg,
                'scan_run_id': scan_run.pk,
            }
class CiscoSwitchScanJob(JobRunner):

    class Meta:
        name = "Cisco Switch Scan"
    def run(self, scanner_id: int) -> Dict[str, Any]:

        scanner = Scanner.objects.get(pk=scanner_id)
        scan_run = ScanRun.objects.create(
            scanner=scanner,
            status=ScanRunStatusChoices.STATUS_RUNNING,
            started_at=datetime.now(timezone.utc)
        )
        log_lines = []
        try:
            log_lines.append(f"Starting Cisco switch scan for {scanner.target_hostname}")
            self.logger.info(f"Connecting to: {scanner.target_hostname}")
            if scanner.connection_protocol == ConnectionProtocolChoices.PROTOCOL_SSH:
                return self._scan_via_ssh(scanner, scan_run, log_lines)
            elif scanner.connection_protocol == ConnectionProtocolChoices.PROTOCOL_SNMP_V2C:
                return self._scan_via_snmp_v2c(scanner, scan_run, log_lines)
            elif scanner.connection_protocol == ConnectionProtocolChoices.PROTOCOL_SNMP_V3:
                return self._scan_via_snmp_v3(scanner, scan_run, log_lines)
            else:
                raise ValueError(f"Unsupported connection protocol: {scanner.connection_protocol}")
        except Exception as e:
            error_msg = f"Scan failed: {str(e)}"
            log_lines.append(f"ERROR: {error_msg}")
            self.logger.error(error_msg, exc_info=True)
            scan_run.status = ScanRunStatusChoices.STATUS_FAILED
            scan_run.completed_at = datetime.now(timezone.utc)
            scan_run.error_message = error_msg
            scan_run.log_output = '\n'.join(log_lines)
            scan_run.save()
            return {
                'success': False,
                'error': error_msg,
                'scan_run_id': scan_run.pk,
            }
    def _scan_via_ssh(self, scanner, scan_run, log_lines) -> Dict[str, Any]:

        try:

            original_kex = paramiko.Transport._preferred_kex if hasattr(paramiko.Transport, '_preferred_kex') else None
            original_keys = paramiko.Transport._preferred_keys if hasattr(paramiko.Transport, '_preferred_keys') else None
            original_ciphers = paramiko.Transport._preferred_ciphers if hasattr(paramiko.Transport, '_preferred_ciphers') else None
            try:
                paramiko.Transport._preferred_kex = (
                    'diffie-hellman-group1-sha1',
                    'diffie-hellman-group14-sha1',
                    'diffie-hellman-group-exchange-sha1',
                    'diffie-hellman-group-exchange-sha256',
                )
                paramiko.Transport._preferred_keys = (
                    'ssh-rsa',
                    'ssh-dss',
                    'ecdsa-sha2-nistp256',
                    'ecdsa-sha2-nistp384',
                    'ecdsa-sha2-nistp521',
                )
                paramiko.Transport._preferred_ciphers = (
                    'aes128-cbc',
                    'aes192-cbc',
                    'aes256-cbc',
                    '3des-cbc',
                    'aes128-ctr',
                    'aes192-ctr',
                    'aes256-ctr',
                )
                log_lines.append(f"Configured legacy SSH algorithms for IOS 12.4 compatibility")
                device_params = {
                    'device_type': 'cisco_ios',
                    'host': scanner.target_hostname,
                    'username': scanner.ssh_username,
                    'password': scanner.ssh_password,
                    'port': scanner.ssh_port or 22,
                    'timeout': 60,
                    'session_timeout': 60,
                    'conn_timeout': 60,
                    'auth_timeout': 60,
                    'banner_timeout': 60,
                    'blocking_timeout': 60,
                    'ssh_config_file': None,
                    'allow_agent': False,
                    'use_keys': False,
                    'key_file': None,
                }
                log_lines.append(f"Attempting SSH connection to {scanner.target_hostname}:{scanner.ssh_port or 22}...")
                connection = ConnectHandler(**device_params)
                log_lines.append("✓ SSH connection established")
                log_lines.append("Gathering device information...")
                output = connection.send_command('show run | include hostname')
                hostname = output.split()[-1] if output else scanner.target_hostname
                log_lines.append(f"  Hostname: {hostname}")
                version_output = connection.send_command('show version')
                model = self._parse_model(version_output)
                serial = self._parse_serial(version_output)
                os_version = self._parse_os_version(version_output)
                log_lines.append(f"  Model: {model}")
                log_lines.append(f"  Serial: {serial}")
                log_lines.append(f"  OS Version: {os_version}")
                with transaction.atomic():

                    site = scanner.site
                    if not site:
                        site, _ = Site.objects.get_or_create(
                            slug='auto-discovery',
                            defaults={
                                'name': 'Auto Discovery',
                                'status': 'active',
                                'description': 'Default site for auto-discovered devices'
                            }
                        )
                        log_lines.append(f"Using default site: {site.name}")
                    manufacturer, _ = Manufacturer.objects.get_or_create(
                        name='Cisco',
                        slug='cisco'
                    )
                    device_type, _ = DeviceType.objects.get_or_create(
                        manufacturer=manufacturer,
                        model=model or 'Unknown',
                        defaults={'slug': (model or 'unknown').lower().replace(' ', '-')}
                    )
                    device_role, _ = DeviceRole.objects.get_or_create(
                        name='Network Switch',
                        slug='network-switch',
                        defaults={'color': '2196f3'}
                    )
                    device, created = Device.objects.get_or_create(
                        name=hostname,
                        defaults={
                            'device_type': device_type,
                            'role': device_role,
                            'site': site,
                            'serial': serial,
                            'comments': f'Discovered by Auto Discovery on {scan_run.started_at.strftime("%Y-%m-%d %H:%M")}',
                        }
                    )
                    if not created:
                        device.device_type = device_type
                        device.role = device_role
                        if serial:
                            device.serial = serial
                        device.comments = f'Updated by Auto Discovery on {scan_run.started_at.strftime("%Y-%m-%d %H:%M")}'
                        device.save()
                    log_lines.append(f"{'Created' if created else 'Updated'} device: {device.name}")
                    DiscoveredDevice.objects.create(
                        scan_run=scan_run,
                        device=device,
                        action='created' if created else 'updated',
                        discovered_data={
                            'hostname': hostname,
                            'model': model,
                            'serial': serial,
                            'os_version': os_version,
                            'raw_version': version_output[:500],
                        }
                    )
                    log_lines.append("Discovering interfaces...")
                    interface_output = connection.send_command('show interfaces status')
                    if not interface_output or len(interface_output.strip()) < 10:
                        log_lines.append("  'show interfaces status' returned no data, trying router command...")
                        interface_output = connection.send_command('show ip interface brief')
                        log_lines.append("  Using 'show ip interface brief' (router command)")
                    else:
                        log_lines.append("  Using 'show interfaces status' (switch command)")
                    log_lines.append(f"  Interface output length: {len(interface_output)} chars")
                    interfaces_created = self._process_interfaces(device, interface_output, log_lines)
                    log_lines.append("Discovering VLANs...")
                    vlan_output = connection.send_command('show vlan brief')
                    if vlan_output and len(vlan_output.strip()) > 10:
                        vlans_created = self._process_vlans(scanner.site, vlan_output, log_lines)
                    else:
                        log_lines.append("  (VLANs not available - device may be a router)")
                        vlans_created = 0
                    log_lines.append("Discovering VLAN-to-interface assignments...")
                    vlan_assignments = self._ssh_assign_vlans_to_interfaces(connection, device, log_lines)
                    connection.disconnect()
                    log_lines.append("✓ Connection closed")
            finally:
                if original_kex is not None:
                    paramiko.Transport._preferred_kex = original_kex
                if original_keys is not None:
                    paramiko.Transport._preferred_keys = original_keys
                if original_ciphers is not None:
                    paramiko.Transport._preferred_ciphers = original_ciphers
            scan_run.status = ScanRunStatusChoices.STATUS_COMPLETED
            scan_run.completed_at = datetime.now(timezone.utc)
            scan_run.devices_discovered = 1
            scan_run.interfaces_discovered = interfaces_created
            scan_run.vlans_discovered = vlans_created
            scan_run.log_output = '\n'.join(log_lines)
            scan_run.save()
            self.logger.info(f"SSH scan completed successfully - {vlan_assignments} VLAN assignments")
            return {
                'success': True,
                'device': hostname,
                'interfaces': interfaces_created,
                'vlans': vlans_created,
                'vlan_assignments': vlan_assignments,
                'scan_run_id': scan_run.pk,
            }
        except Exception as e:
            raise
    def _parse_model(self, version_output: str) -> str:
        for line in version_output.split('\n'):
            if 'cisco' in line.lower() and ('bytes' in line.lower() or 'processor' in line.lower()):
                parts = line.split()
                for i, part in enumerate(parts):
                    if part.lower() == 'cisco' and i + 1 < len(parts):
                        return parts[i + 1]
        return 'Unknown'
    def _parse_serial(self, version_output: str) -> str:
        for line in version_output.split('\n'):
            if 'serial' in line.lower() or 'system serial number' in line.lower():
                parts = line.split(':')
                if len(parts) > 1:
                    return parts[-1].strip().split()[0]
        return ''
    def _parse_os_version(self, version_output: str) -> str:
        for line in version_output.split('\n'):
            if 'version' in line.lower() and ('ios' in line.lower() or 'software' in line.lower()):
                return line.strip()
        return ''
    def _process_interfaces(self, device: Device, interface_output: str, log_lines: list) -> int:
        created_count = 0
        lines = interface_output.split('\n')
        log_lines.append(f"  Processing {len(lines)} lines of interface output")
        if lines and 'Interface' in lines[0] and 'IP-Address' in lines[0]:
            start_line = 1
            log_lines.append(f"  Detected router format (show ip interface brief)")
        else:
            start_line = 2
            log_lines.append(f"  Detected switch format (show interfaces status)")
        for line in lines[start_line:]:
            if not line.strip():
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            interface_name = parts[0]
            if interface_name.lower() in ['interface', 'port', '----']:
                continue
            interface_type = 'other'
            if 'ethernet' in interface_name.lower() or 'eth' in interface_name.lower():
                interface_type = '1000base-t'
            elif 'gigabit' in interface_name.lower():
                interface_type = '1000base-t'
            elif 'fast' in interface_name.lower():
                interface_type = '100base-tx'
            elif 'serial' in interface_name.lower():
                interface_type = 'other'
            interface, created = Interface.objects.get_or_create(
                device=device,
                name=interface_name,
                defaults={
                    'type': interface_type,
                    'enabled': True,
                }
            )
            if created:
                created_count += 1
                log_lines.append(f"  Created interface: {interface_name}")
            else:
                log_lines.append(f"  Interface already exists: {interface_name}")
        log_lines.append(f"  Total interfaces created: {created_count}")
        return created_count
    def _process_vlans(self, site, vlan_output: str, log_lines: list) -> int:
        created_count = 0
        for line in vlan_output.split('\n')[2:]:
            if not line.strip():
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            try:
                vlan_id = int(parts[0])
                vlan_name = parts[1]
                vlan, created = VLAN.objects.get_or_create(
                    vid=vlan_id,
                    name=vlan_name,
                    defaults={
                        'site': site,
                    }
                )
                if created:
                    created_count += 1
                    log_lines.append(f"  Created VLAN {vlan_id}: {vlan_name}")
            except (ValueError, IndexError):
                continue
        return created_count
    def _ssh_assign_vlans_to_interfaces(self, connection, device, log_lines) -> int:
        try:

            switchport_output = connection.send_command('show interfaces switchport')
            
            if not switchport_output or len(switchport_output.strip()) < 10:
                log_lines.append("  'show interfaces switchport' returned no data")
                return 0
            
            log_lines.append(f"  Parsing switchport output ({len(switchport_output)} chars)...")
            
            assignment_count = 0
            current_interface = None
            current_mode = None
            
            for line in switchport_output.split('\n'):
                line = line.strip()
                
                if line.startswith('Name:'):

                    if current_interface:
                        current_interface = None
                        current_mode = None
                    
                    parts = line.split(':', 1)
                    if len(parts) > 1:
                        interface_name = parts[1].strip()
                        
                        try:
                            current_interface = Interface.objects.get(device=device, name=interface_name)
                        except Interface.DoesNotExist:

                            if interface_name.startswith('Et'):
                                interface_name = interface_name.replace('Et', 'Ethernet')
                                try:
                                    current_interface = Interface.objects.get(device=device, name=interface_name)
                                except Interface.DoesNotExist:
                                    current_interface = None
                
                elif line.startswith('Switchport:') and current_interface:
                    if 'Disabled' in line:
                        current_interface = None
                
                elif line.startswith('Administrative Mode:') and current_interface:
                    if 'static access' in line.lower() or 'access' in line.lower():
                        current_mode = 'access'
                    elif 'trunk' in line.lower():
                        current_mode = 'trunk'
                
                elif line.startswith('Access Mode VLAN:') and current_interface and current_mode == 'access':

                    parts = line.split(':',1)
                    if len(parts) > 1:
                        vlan_info = parts[1].strip()
                        vlan_parts = vlan_info.split()
                        if vlan_parts:
                            try:
                                vlan_id = int(vlan_parts[0])
                                
                                try:
                                    vlan = VLAN.objects.get(vid=vlan_id)
                                    
                                    current_interface.untagged_vlan = vlan
                                    current_interface.mode = 'access'
                                    current_interface.save()
                                    assignment_count += 1
                                    log_lines.append(f"  Access port {current_interface.name}: VLAN {vlan_id}")
                                
                                except VLAN.DoesNotExist:
                                    log_lines.append(f"  Warning: VLAN {vlan_id} not found for {current_interface.name}")
                            
                            except ValueError:
                                continue
                
                elif line.startswith('Trunking VLANs Enabled:') and current_interface and current_mode == 'trunk':

                    parts = line.split(':', 1)
                    if len(parts) > 1:
                        vlan_list_str = parts[1].strip()
                        
                        if vlan_list_str.upper() in ['ALL', 'NONE']:
                            continue
                        
                        vlan_ids = []
                        for vlan_part in vlan_list_str.split(','):
                            vlan_part = vlan_part.strip()
                            
                            if '-' in vlan_part:

                                try:
                                    start, end = vlan_part.split('-')
                                    start_id = int(start.strip())
                                    end_id = int(end.strip())
                                    
                                    if end_id - start_id < 100:
                                        vlan_ids.extend(range(start_id, end_id + 1))
                                except ValueError:
                                    continue
                            else:

                                try:
                                    vlan_ids.append(int(vlan_part))
                                except ValueError:
                                    continue
                        
                        if vlan_ids:
                            current_interface.mode = 'tagged'
                            current_interface.save()
                            
                            vlans_added = 0
                            for vlan_id in vlan_ids:
                                try:
                                    vlan = VLAN.objects.get(vid=vlan_id)
                                    current_interface.tagged_vlans.add(vlan)
                                    vlans_added += 1
                                except VLAN.DoesNotExist:
                                    continue
                            
                            if vlans_added > 0:
                                assignment_count += vlans_added
                                log_lines.append(f"  Trunk port {current_interface.name}: {vlans_added} tagged VLANs")
            
            log_lines.append(f"  Total VLAN assignments: {assignment_count}")
            return assignment_count
        
        except Exception as e:
            log_lines.append(f"  Error during VLAN assignment: {str(e)}")
            return 0
    def _scan_via_snmp_v2c(self, scanner, scan_run, log_lines) -> Dict[str, Any]:
        log_lines.append(f"Using SNMP v2c protocol")
        log_lines.append(f"Community string: {'*' * len(scanner.snmp_community)}")
        if not PYSNMP_AVAILABLE:
            raise Exception("SNMP scanning is not available. pysnmp library not properly installed.")
        try:
            log_lines.append("Creating SNMP credentials...")
            auth_data = CommunityData(scanner.snmp_community, mpModel=1)
            log_lines.append(f"Creating transport target for {scanner.target_hostname}:{scanner.snmp_port or 161}")
            target = UdpTransportTarget((scanner.target_hostname, scanner.snmp_port or 161), timeout=10, retries=3)
            log_lines.append("Querying device info...")
            device_info = self._snmp_get_device_info(auth_data, target, log_lines)
            log_lines.append(f"Device info received: {device_info}")
            hostname = device_info['hostname']
            model = device_info['model']
            with transaction.atomic():
                device = self._create_or_update_device(
                    hostname, model, '', device_info['description'],
                    scanner.site, scan_run, log_lines
                )
                interfaces_created = self._snmp_get_interfaces(auth_data, target, device, log_lines)
                vlans_created = self._snmp_get_vlans(auth_data, target, scanner.site, log_lines)
                
                access_assignments = self._snmp_assign_vlans_to_interfaces(auth_data, target, device, log_lines)
                
                trunk_assignments = self._snmp_assign_trunk_vlans_to_interfaces(auth_data, target, device, log_lines)
                
                vlan_assignments = access_assignments + trunk_assignments
            scan_run.status = ScanRunStatusChoices.STATUS_COMPLETED
            scan_run.completed_at = datetime.now(timezone.utc)
            scan_run.devices_discovered = 1
            scan_run.interfaces_discovered = interfaces_created
            scan_run.vlans_discovered = vlans_created
            scan_run.log_output = '\n'.join(log_lines)
            scan_run.save()
            self.logger.info(f"SNMP v2c scan completed successfully - {vlan_assignments} VLAN assignments")
            return {
                'success': True,
                'device': hostname,
                'interfaces': interfaces_created,
                'vlans': vlans_created,
                'scan_run_id': scan_run.pk,
            }
        except Exception as e:
            log_lines.append(f"ERROR: {str(e)}")
            import traceback
            log_lines.append(f"Traceback: {traceback.format_exc()}")
            scan_run.log_output = '\n'.join(log_lines)
            scan_run.save()
            raise
    def _scan_via_snmp_v3(self, scanner, scan_run, log_lines) -> Dict[str, Any]:
        log_lines.append(f"Using SNMP v3 protocol")
        log_lines.append(f"Username: {scanner.snmp_v3_username}")
        if not PYSNMP_AVAILABLE:
            raise Exception("SNMP scanning is not available. pysnmp library not properly installed.")
        try:
            auth_protocol = usmHMACMD5AuthProtocol
            priv_protocol = usmDESPrivProtocol
            if scanner.snmp_v3_auth_protocol:
                if scanner.snmp_v3_auth_protocol.upper() == 'MD5':
                    auth_protocol = usmHMACMD5AuthProtocol
                elif scanner.snmp_v3_auth_protocol.upper() in ['SHA', 'SHA1']:
                    auth_protocol = usmHMACSHAAuthProtocol
            if scanner.snmp_v3_priv_protocol:
                if scanner.snmp_v3_priv_protocol.upper() == 'DES':
                    priv_protocol = usmDESPrivProtocol
                elif scanner.snmp_v3_priv_protocol.upper() in ['AES', 'AES128']:
                    priv_protocol = usmAesCfb128Protocol
            auth_data = UsmUserData(
                scanner.snmp_v3_username,
                scanner.snmp_v3_auth_key or None,
                scanner.snmp_v3_priv_key or None,
                authProtocol=auth_protocol if scanner.snmp_v3_auth_key else None,
                privProtocol=priv_protocol if scanner.snmp_v3_priv_key else None
            )
            target = UdpTransportTarget((scanner.target_hostname, scanner.snmp_port or 161), timeout=10, retries=3)
            device_info = self._snmp_get_device_info(auth_data, target, log_lines)
            hostname = device_info['hostname']
            model = device_info['model']
            with transaction.atomic():
                device = self._create_or_update_device(
                    hostname, model, '', device_info['description'],
                    scanner.site, scan_run, log_lines
                )
                interfaces_created = self._snmp_get_interfaces(auth_data, target, device, log_lines)
                vlans_created = self._snmp_get_vlans(auth_data, target, scanner.site, log_lines)
                
                access_assignments = self._snmp_assign_vlans_to_interfaces(auth_data, target, device, log_lines)
                
                trunk_assignments = self._snmp_assign_trunk_vlans_to_interfaces(auth_data, target, device, log_lines)
                
                vlan_assignments = access_assignments + trunk_assignments
            scan_run.status = ScanRunStatusChoices.STATUS_COMPLETED
            scan_run.completed_at = datetime.now(timezone.utc)
            scan_run.devices_discovered = 1
            scan_run.interfaces_discovered = interfaces_created
            scan_run.vlans_discovered = vlans_created
            scan_run.log_output = '\n'.join(log_lines)
            scan_run.save()
            self.logger.info(f"SNMP v3 scan completed successfully - {vlan_assignments} VLAN assignments")
            return {
                'success': True,
                'device': hostname,
                'interfaces': interfaces_created,
                'vlans': vlans_created,
                'scan_run_id': scan_run.pk,
            }
        except Exception as e:
            raise
    def _snmp_get_device_info(self, auth_data, target, log_lines) -> Dict[str, str]:
        log_lines.append("Querying device information via SNMP...")
        engine = SnmpEngine()
        result = getCmd(
            engine,
            auth_data,
            target,
            ContextData(),
            ObjectType(ObjectIdentity('1.3.6.1.2.1.1.1.0')),
            ObjectType(ObjectIdentity('1.3.6.1.2.1.1.5.0'))
        )
        if result is None:
            raise Exception("SNMP query returned None - connection or timeout issue")
        error_indication, error_status, error_index, var_binds = result
        if error_indication:
            raise Exception(f"SNMP error: {error_indication}")
        elif error_status:
            raise Exception(f"SNMP error: {error_status.prettyPrint()}")
        sys_descr = str(var_binds[0][1])
        sys_name = str(var_binds[1][1])
        log_lines.append(f"  Hostname: {sys_name}")
        log_lines.append(f"  Description: {sys_descr[:100]}...")
        model = 'Unknown'
        if 'cisco' in sys_descr.lower():
            parts = sys_descr.split()
            for i, part in enumerate(parts):
                if part.lower() == 'cisco' and i + 1 < len(parts):
                    model = parts[i + 1]
                    break
        return {
            'hostname': sys_name or 'unknown',
            'model': model,
            'description': sys_descr
        }
    def _snmp_get_interfaces(self, auth_data, target, device, log_lines) -> int:
        log_lines.append("Discovering interfaces via SNMP...")
        engine = SnmpEngine()
        created_count = 0
        base_oid = '1.3.6.1.2.1.2.2.1.2'
        error_indication, error_status, error_index, var_binds = bulkCmd(
            engine,
            auth_data,
            target,
            ContextData(),
            0, 25,
            ObjectType(ObjectIdentity(base_oid))
        )
        if error_indication:
            log_lines.append(f"  SNMP error: {error_indication}")
            return 0
        elif error_status:
            log_lines.append(f"  SNMP error: {error_status.prettyPrint()}")
            return 0
        for var_bind_list in var_binds:

            if isinstance(var_bind_list, list) and len(var_bind_list) > 0:
                var_bind = var_bind_list[0]
                oid, value = var_bind
            else:
                log_lines.append(f"  Warning: Unexpected format: {var_bind_list}")
                continue
            interface_name = str(value)
            if not str(oid).startswith(base_oid):
                break
            if interface_name and interface_name != 'No Such Instance currently exists at this OID':
                interface_type = 'other'
                if 'ethernet' in interface_name.lower() or 'eth' in interface_name.lower():
                    interface_type = '1000base-t'
                elif 'gigabit' in interface_name.lower():
                    interface_type = '1000base-t'
                elif 'fast' in interface_name.lower():
                    interface_type = '100base-tx'
                interface, created = Interface.objects.get_or_create(
                    device=device,
                    name=interface_name,
                    defaults={
                        'type': interface_type,
                        'enabled': True,
                    }
                )
                if created:
                    created_count += 1
                    log_lines.append(f"  Created interface: {interface_name}")
        log_lines.append(f"  Total interfaces created: {created_count}")
        return created_count
    def _snmp_get_vlans(self, auth_data, target, site, log_lines) -> int:
        log_lines.append("Discovering VLANs via SNMP...")
        engine = SnmpEngine()
        created_count = 0
        base_oid = '1.3.6.1.4.1.9.9.46.1.3.1.1.4'
        error_indication, error_status, error_index, var_binds = bulkCmd(
            engine,
            auth_data,
            target,
            ContextData(),
            0, 25,
            ObjectType(ObjectIdentity(base_oid))
        )
        if error_indication:
            log_lines.append(f"  SNMP error (VLANs may not be available): {error_indication}")
            return 0
        elif error_status:
            log_lines.append(f"  SNMP error: {error_status.prettyPrint()}")
            return 0
        for var_bind_list in var_binds:

            if isinstance(var_bind_list, list) and len(var_bind_list) > 0:
                var_bind = var_bind_list[0]
                oid, value = var_bind
            else:
                log_lines.append(f"  Warning: Unexpected format: {var_bind_list}")
                continue
            vlan_name = str(value)
            if not str(oid).startswith(base_oid):
                break
            oid_str = str(oid)
            vlan_id_match = oid_str.split('.')[-1]
            try:
                vlan_id = int(vlan_id_match)
                if vlan_name and vlan_name != 'No Such Instance currently exists at this OID' and 1 <= vlan_id <= 4094:
                    vlan, created = VLAN.objects.get_or_create(
                        vid=vlan_id,
                        name=vlan_name,
                        defaults={'site': site}
                    )
                    if created:
                        created_count += 1
                        log_lines.append(f"  Created VLAN {vlan_id}: {vlan_name}")
            except (ValueError, IndexError):
                continue
        log_lines.append(f"  Total VLANs created: {created_count}")
        return created_count
    def _snmp_assign_vlans_to_interfaces(self, auth_data, target, device, log_lines) -> int:
        log_lines.append("Assigning VLANs to interfaces via SNMP...")
        
        engine = SnmpEngine()
        assignment_count = 0
        
        base_oid = '1.3.6.1.4.1.9.9.68.1.2.2.1.2'
        
        error_indication, error_status, error_index, var_binds = bulkCmd(
            engine,
            auth_data,
            target,
            ContextData(),
            0, 25,
            ObjectType(ObjectIdentity(base_oid))
        )
        
        if error_indication:
            log_lines.append(f"  SNMP error (VLAN assignments may not be available): {error_indication}")
            return 0
        elif error_status:
            log_lines.append(f"  SNMP error: {error_status.prettyPrint()}")
            return 0
        
        for var_bind_list in var_binds:

            if isinstance(var_bind_list, list) and len(var_bind_list) > 0:
                var_bind = var_bind_list[0]
                oid, value = var_bind
            else:
                continue
            
            if not str(oid).startswith(base_oid):
                break
            
            oid_str = str(oid)
            parts = oid_str.split('.')
            if len(parts) < 2:
                continue
            
            try:

                if_index = int(parts[-1])
                vlan_id = int(value)
                
                if not (1 <= vlan_id <= 4094):
                    continue
                
                
                interfaces = Interface.objects.filter(device=device).order_by('id')
                
                if if_index <= interfaces.count():
                    interface = interfaces[if_index - 1]
                    
                    try:
                        vlan = VLAN.objects.get(vid=vlan_id)
                        
                        if not interface.untagged_vlan:
                            interface.untagged_vlan = vlan
                            interface.mode = 'access'
                            interface.save()
                            assignment_count += 1
                            log_lines.append(f"  Assigned VLAN {vlan_id} to {interface.name}")
                    
                    except VLAN.DoesNotExist:
                        log_lines.append(f"  Warning: VLAN {vlan_id} not found for interface {interface.name}")
                        continue
            
            except (ValueError, IndexError) as e:
                continue
        
        log_lines.append(f"  Total VLAN assignments: {assignment_count}")
        return assignment_count
    def _snmp_assign_trunk_vlans_to_interfaces(self, auth_data, target, device, log_lines) -> int:
        log_lines.append("Discovering trunk port VLANs via SNMP...")
        
        engine = SnmpEngine()
        assignment_count = 0
        
        base_oid = '1.3.6.1.4.1.9.9.46.1.6.1.1.4'
        
        error_indication, error_status, error_index, var_binds = bulkCmd(
            engine,
            auth_data,
            target,
            ContextData(),
            0, 25,
            ObjectType(ObjectIdentity(base_oid))
        )
        
        if error_indication:
            log_lines.append(f"  SNMP error (trunk VLANs may not be available): {error_indication}")
            return 0
        elif error_status:
            log_lines.append(f"  SNMP error: {error_status.prettyPrint()}")
            return 0
        
        for var_bind_list in var_binds:
            if isinstance(var_bind_list, list) and len(var_bind_list) > 0:
                var_bind = var_bind_list[0]
                oid, value = var_bind
            else:
                continue
            
            if not str(oid).startswith(base_oid):
                break
            
            oid_str = str(oid)
            parts = oid_str.split('.')
            if len(parts) < 2:
                continue
            
            try:
                if_index = int(parts[-1])
                
                vlan_bitmap = bytes(value)
                
                if not vlan_bitmap:
                    continue
                
                allowed_vlans = []
                for byte_idx, byte_val in enumerate(vlan_bitmap):
                    for bit_idx in range(8):
                        if byte_val & (1 << (7 - bit_idx)):
                            vlan_id = (byte_idx * 8) + bit_idx + 1
                            if 1 <= vlan_id <= 4094:
                                allowed_vlans.append(vlan_id)
                
                if not allowed_vlans:
                    continue
                
                interfaces = Interface.objects.filter(device=device).order_by('id')
                
                if if_index <= interfaces.count():
                    interface = interfaces[if_index - 1]
                    
                    interface.mode = 'tagged'
                    interface.save()
                    
                    vlans_added = 0
                    for vlan_id in allowed_vlans:
                        try:
                            vlan = VLAN.objects.get(vid=vlan_id)
                            interface.tagged_vlans.add(vlan)
                            vlans_added += 1
                        except VLAN.DoesNotExist:
                            continue
                    
                    if vlans_added > 0:
                        assignment_count += vlans_added
                        log_lines.append(f"  Trunk {interface.name}: added {vlans_added} tagged VLANs")
            
            except (ValueError, IndexError, TypeError) as e:
                continue
        
        log_lines.append(f"  Total trunk VLAN assignments: {assignment_count}")
        return assignment_count
    def _create_or_update_device(self, hostname, model, serial, description, site, scan_run, log_lines):

        if not site:
            site, _ = Site.objects.get_or_create(
                slug='auto-discovery',
                defaults={
                    'name': 'Auto Discovery',
                    'status': 'active',
                    'description': 'Default site for auto-discovered devices'
                }
            )
            log_lines.append(f"Using default site: {site.name}")
        manufacturer, _ = Manufacturer.objects.get_or_create(
            name='Cisco',
            slug='cisco'
        )
        device_type, _ = DeviceType.objects.get_or_create(
            manufacturer=manufacturer,
            model=model or 'Unknown',
            defaults={'slug': (model or 'unknown').lower().replace(' ', '-')}
        )
        device_role, _ = DeviceRole.objects.get_or_create(
            name='Network Switch',
            slug='network-switch',
            defaults={'color': '2196f3'}
        )
        device, created = Device.objects.get_or_create(
            name=hostname,
            defaults={
                'device_type': device_type,
                'role': device_role,
                'site': site,
                'serial': serial,
                'comments': f'Discovered by Auto Discovery on {scan_run.started_at.strftime("%Y-%m-%d %H:%M")}',
            }
        )
        if not created:
            device.device_type = device_type
            device.role = device_role
            if serial:
                device.serial = serial
            device.comments = f'Updated by Auto Discovery on {scan_run.started_at.strftime("%Y-%m-%d %H:%M")}'
            device.save()
        log_lines.append(f"{'Created' if created else 'Updated'} device: {device.name}")
        DiscoveredDevice.objects.create(
            scan_run=scan_run,
            device=device,
            action='created' if created else 'updated',
            discovered_data={
                'hostname': hostname,
                'model': model,
                'serial': serial,
                'description': description[:500]
            }
        )
        return device