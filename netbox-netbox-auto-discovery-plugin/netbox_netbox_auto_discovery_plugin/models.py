from django.contrib.postgres.fields import ArrayField
from django.core.exceptions import ValidationError
from django.core.validators import MinValueValidator, MaxValueValidator, validate_ipv46_address
from django.db import models
from django.urls import reverse
from netbox.models import NetBoxModel
import ipaddress
import re

from .choices import (
    ScannerTypeChoices,
    ScannerStatusChoices,
    ScanRunStatusChoices,
    ConnectionProtocolChoices,
)


class Scanner(NetBoxModel):

    name = models.CharField(
        max_length=100,
        unique=True,
        help_text="Unique name for this scanner"
    )

    scanner_type = models.CharField(
        max_length=50,
        choices=ScannerTypeChoices,
        help_text="Type of scanner (Network Range or Cisco Switch)"
    )

    status = models.CharField(
        max_length=50,
        choices=ScannerStatusChoices,
        default=ScannerStatusChoices.STATUS_ACTIVE,
        help_text="Current status of the scanner"
    )

    description = models.TextField(
        blank=True,
        help_text="Optional description for this scanner"
    )

    cidr_range = models.CharField(
        max_length=100,
        blank=True,
        help_text="CIDR notation for network range scan (e.g., 192.168.1.0/24)"
    )

    target_hostname = models.CharField(
        max_length=255,
        blank=True,
        help_text="Hostname or IP address of the target device"
    )

    connection_protocol = models.CharField(
        max_length=50,
        choices=ConnectionProtocolChoices,
        blank=True,
        help_text="Protocol to use for device connection"
    )

    ssh_username = models.CharField(
        max_length=100,
        blank=True,
        help_text="SSH username for device access"
    )

    ssh_password = models.CharField(
        max_length=255,
        blank=True,
        help_text="SSH password (will be encrypted)"
    )

    ssh_port = models.PositiveIntegerField(
        default=22,
        validators=[MinValueValidator(1), MaxValueValidator(65535)],
        help_text="SSH port number"
    )

    snmp_community = models.CharField(
        max_length=100,
        blank=True,
        help_text="SNMP community string (v2c)"
    )

    snmp_port = models.PositiveIntegerField(
        default=161,
        validators=[MinValueValidator(1), MaxValueValidator(65535)],
        help_text="SNMP port number"
    )

    snmp_v3_username = models.CharField(
        max_length=100,
        blank=True,
        help_text="SNMPv3 username"
    )

    snmp_v3_auth_protocol = models.CharField(
        max_length=20,
        blank=True,
        help_text="SNMPv3 authentication protocol (MD5, SHA)"
    )

    snmp_v3_auth_key = models.CharField(
        max_length=255,
        blank=True,
        help_text="SNMPv3 authentication key"
    )

    snmp_v3_priv_protocol = models.CharField(
        max_length=20,
        blank=True,
        help_text="SNMPv3 privacy protocol (DES, AES)"
    )

    snmp_v3_priv_key = models.CharField(
        max_length=255,
        blank=True,
        help_text="SNMPv3 privacy key"
    )

    scan_interval_hours = models.PositiveIntegerField(
        blank=True,
        null=True,
        help_text="Automatic scan interval in hours (leave blank for manual only)"
    )

    site = models.ForeignKey(
        to='dcim.Site',
        on_delete=models.SET_NULL,
        related_name='scanners',
        blank=True,
        null=True,
        help_text="Associated NetBox site for discovered resources"
    )

    class Meta:
        ordering = ('name',)
        verbose_name = 'Scanner'
        verbose_name_plural = 'Scanners'

    def __str__(self):
        return f"{self.name} ({self.get_scanner_type_display()})"

    def get_absolute_url(self):
        return reverse('plugins:netbox_netbox_auto_discovery_plugin:scanner', args=[self.pk])

    def clean(self):
        super().clean()
        errors = {}

        if self.scanner_type == ScannerTypeChoices.TYPE_NETWORK_RANGE:
            if not self.cidr_range:
                errors['cidr_range'] = 'CIDR range is required for network range scans.'
            else:
                try:
                    network = ipaddress.ip_network(self.cidr_range, strict=False)
                    if network.num_addresses > 16777216:
                        errors['cidr_range'] = f'CIDR range is too large ({network.num_addresses:,} addresses). Consider scanning smaller subnets.'
                except ValueError as e:
                    errors['cidr_range'] = f'Invalid CIDR notation: {self.cidr_range}. Expected format: 192.168.1.0/24'

        elif self.scanner_type == ScannerTypeChoices.TYPE_CISCO_SWITCH:
            if not self.target_hostname:
                errors['target_hostname'] = 'Target hostname or IP address is required for Cisco switch scans.'
            else:
                if not self._is_valid_hostname_or_ip(self.target_hostname):
                    errors['target_hostname'] = f'Invalid hostname or IP address: {self.target_hostname}'

            if not self.connection_protocol:
                errors['connection_protocol'] = 'Connection protocol is required for Cisco switch scans.'

            if self.connection_protocol == ConnectionProtocolChoices.PROTOCOL_SSH:
                if not self.ssh_username:
                    errors['ssh_username'] = 'SSH username is required when using SSH protocol.'
                if not self.ssh_password:
                    errors['ssh_password'] = 'SSH password is required when using SSH protocol.'

            elif self.connection_protocol == ConnectionProtocolChoices.PROTOCOL_SNMP_V2C:
                if not self.snmp_community:
                    errors['snmp_community'] = 'SNMP community string is required for SNMP v2c protocol.'

            elif self.connection_protocol == ConnectionProtocolChoices.PROTOCOL_SNMP_V3:
                if not self.snmp_v3_username:
                    errors['snmp_v3_username'] = 'SNMP v3 username is required for SNMP v3 protocol.'
                
                if not self.snmp_v3_auth_protocol:
                    errors['snmp_v3_auth_protocol'] = 'SNMP v3 authentication protocol is required.'
                elif self.snmp_v3_auth_protocol.upper() not in ['MD5', 'SHA', 'SHA1']:
                    errors['snmp_v3_auth_protocol'] = 'Must be MD5, SHA, or SHA1.'
                
                if not self.snmp_v3_auth_key:
                    errors['snmp_v3_auth_key'] = 'SNMP v3 authentication key is required.'
                
                if self.snmp_v3_priv_protocol and not self.snmp_v3_priv_key:
                    errors['snmp_v3_priv_key'] = 'Privacy key is required when privacy protocol is specified.'
                
                if self.snmp_v3_priv_protocol and self.snmp_v3_priv_protocol.upper() not in ['DES', 'AES', 'AES128']:
                    errors['snmp_v3_priv_protocol'] = 'Must be DES, AES, or AES128.'

        if errors:
            raise ValidationError(errors)

    def _is_valid_hostname_or_ip(self, value):
        try:
            validate_ipv46_address(value)
            return True
        except ValidationError:
            pass

        hostname_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        if re.match(hostname_pattern, value) and len(value) <= 253:
            return True

        return False


class ScanRun(NetBoxModel):

    scanner = models.ForeignKey(
        to='Scanner',
        on_delete=models.CASCADE,
        related_name='scan_runs',
        help_text="Scanner that executed this run"
    )

    status = models.CharField(
        max_length=50,
        choices=ScanRunStatusChoices,
        default=ScanRunStatusChoices.STATUS_PENDING,
        help_text="Current status of this scan run"
    )

    started_at = models.DateTimeField(
        blank=True,
        null=True,
        help_text="Timestamp when the scan started"
    )

    completed_at = models.DateTimeField(
        blank=True,
        null=True,
        help_text="Timestamp when the scan completed"
    )

    ips_discovered = models.PositiveIntegerField(
        default=0,
        help_text="Number of IP addresses discovered"
    )

    devices_discovered = models.PositiveIntegerField(
        default=0,
        help_text="Number of devices discovered"
    )

    interfaces_discovered = models.PositiveIntegerField(
        default=0,
        help_text="Number of interfaces discovered"
    )

    vlans_discovered = models.PositiveIntegerField(
        default=0,
        help_text="Number of VLANs discovered"
    )

    log_output = models.TextField(
        blank=True,
        help_text="Detailed log output from the scan"
    )

    error_message = models.TextField(
        blank=True,
        help_text="Error message if the scan failed"
    )

    job_id = models.UUIDField(
        blank=True,
        null=True,
        help_text="NetBox job ID for background execution"
    )

    class Meta:
        ordering = ('-created',)
        verbose_name = 'Scan Run'
        verbose_name_plural = 'Scan Runs'

    def __str__(self):
        return f"{self.scanner.name} - {self.created.strftime('%Y-%m-%d %H:%M')}"

    def get_absolute_url(self):
        return reverse('plugins:netbox_netbox_auto_discovery_plugin:scanrun', args=[self.pk])

    @property
    def duration(self):
        if self.started_at and self.completed_at:
            return self.completed_at - self.started_at
        return None


class DiscoveredDevice(NetBoxModel):

    scan_run = models.ForeignKey(
        to='ScanRun',
        on_delete=models.CASCADE,
        related_name='discovered_devices',
        help_text="Scan run that discovered this device"
    )

    device = models.ForeignKey(
        to='dcim.Device',
        on_delete=models.CASCADE,
        related_name='discovery_records',
        help_text="NetBox device that was discovered/updated"
    )

    action = models.CharField(
        max_length=20,
        choices=[
            ('created', 'Created'),
            ('updated', 'Updated'),
        ],
        help_text="Whether the device was created or updated"
    )

    discovered_data = models.JSONField(
        blank=True,
        null=True,
        help_text="Raw data captured during discovery"
    )

    class Meta:
        ordering = ('-created',)
        verbose_name = 'Discovered Device'
        verbose_name_plural = 'Discovered Devices'

    def __str__(self):
        return f"{self.device.name} ({self.action}) - {self.scan_run}"

    def get_absolute_url(self):
        return reverse('plugins:netbox_netbox_auto_discovery_plugin:discovereddevice', args=[self.pk])


class DiscoveredIPAddress(NetBoxModel):

    scan_run = models.ForeignKey(
        to='ScanRun',
        on_delete=models.CASCADE,
        related_name='discovered_ips',
        help_text="Scan run that discovered this IP address"
    )

    ip_address = models.ForeignKey(
        to='ipam.IPAddress',
        on_delete=models.CASCADE,
        related_name='discovery_records',
        help_text="NetBox IP address that was discovered/updated"
    )

    action = models.CharField(
        max_length=20,
        choices=[
            ('created', 'Created'),
            ('updated', 'Updated'),
        ],
        help_text="Whether the IP address was created or updated"
    )

    hostname = models.CharField(
        max_length=255,
        blank=True,
        help_text="Discovered hostname (if available)"
    )

    open_ports = ArrayField(
        models.PositiveIntegerField(),
        blank=True,
        null=True,
        help_text="List of discovered open ports"
    )

    services = models.JSONField(
        blank=True,
        null=True,
        help_text="Discovered services and their details"
    )

    class Meta:
        ordering = ('-created',)
        verbose_name = 'Discovered IP Address'
        verbose_name_plural = 'Discovered IP Addresses'

    def __str__(self):
        return f"{self.ip_address.address} ({self.action}) - {self.scan_run}"

    def get_absolute_url(self):
        return reverse('plugins:netbox_netbox_auto_discovery_plugin:discoveredipaddress', args=[self.pk])
