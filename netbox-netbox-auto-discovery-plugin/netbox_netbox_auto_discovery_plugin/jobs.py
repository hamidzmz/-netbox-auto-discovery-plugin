import logging
from datetime import datetime, timezone
from typing import Any, Dict

import nmap
import paramiko
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException

from core.jobs import JobRunner
from dcim.models import Device, DeviceType, DeviceRole, Manufacturer, Site, Interface
from ipam.models import IPAddress, VLAN
from django.db import transaction

from .models import Scanner, ScanRun, DiscoveredDevice, DiscoveredIPAddress
from .choices import ScanRunStatusChoices


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
                            'site': scanner.site,
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
                            'raw_version': version_output[:500],  # Store first 500 chars
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

            self.logger.info(f"Scan completed successfully")

            return {
                'success': True,
                'device': hostname,
                'interfaces': interfaces_created,
                'vlans': vlans_created,
                'scan_run_id': scan_run.pk,
            }

        except (NetmikoTimeoutException, NetmikoAuthenticationException) as e:
            error_msg = f"Connection failed: {str(e)}"
            log_lines.append(f"ERROR: {error_msg}")
            self.logger.error(error_msg)

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
