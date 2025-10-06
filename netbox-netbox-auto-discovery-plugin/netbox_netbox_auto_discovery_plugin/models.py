"""Data models for NetBox Auto Discovery Plugin."""

from django.contrib.postgres.fields import ArrayField
from django.core.validators import MinValueValidator, MaxValueValidator
from django.db import models
from django.urls import reverse
from netbox.models import NetBoxModel

from .choices import (
    ScannerTypeChoices,
    ScannerStatusChoices,
    ScanRunStatusChoices,
    ConnectionProtocolChoices,
)


class Scanner(NetBoxModel):
    """
    Represents a network scanner configuration.
    Supports Network Range scans (CIDR-based IP discovery) and Cisco Switch scans (SSH/SNMP device polling).
    """

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

    # Network Range Scan fields
    cidr_range = models.CharField(
        max_length=100,
        blank=True,
        help_text="CIDR notation for network range scan (e.g., 192.168.1.0/24)"
    )

    # Cisco Switch Scan fields
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

    # SSH credentials (encrypted via NetBox secrets mechanism)
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

    # SNMP credentials
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

    # SNMPv3 fields
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

    # Additional options
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


class ScanRun(NetBoxModel):
    """
    Represents a single execution of a scanner.
    Tracks status, timing, and summary metrics for each scan run.
    """

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

    # Summary metrics
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

    # Logs and errors
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
        """Calculate scan duration if both timestamps are available."""
        if self.started_at and self.completed_at:
            return self.completed_at - self.started_at
        return None


class DiscoveredDevice(NetBoxModel):
    """
    Audit record linking a ScanRun to a created/updated NetBox Device.
    Enables tracking which scans contributed to device inventory.
    """

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
    """
    Audit record linking a ScanRun to a created/updated NetBox IPAddress.
    Enables tracking which scans contributed to IP address inventory.
    """

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
