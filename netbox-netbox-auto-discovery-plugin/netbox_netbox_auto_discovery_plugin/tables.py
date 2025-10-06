"""Django Tables2 table definitions for Auto Discovery Plugin."""

import django_tables2 as tables
from netbox.tables import NetBoxTable, ChoiceFieldColumn
from django_tables2.utils import Accessor

from .models import Scanner, ScanRun, DiscoveredDevice, DiscoveredIPAddress


class ScannerTable(NetBoxTable):
    """Table for displaying Scanner objects."""

    name = tables.Column(
        linkify=True,
        verbose_name='Name'
    )
    scanner_type = ChoiceFieldColumn(
        verbose_name='Type'
    )
    status = ChoiceFieldColumn(
        verbose_name='Status'
    )
    site = tables.Column(
        linkify=True,
        verbose_name='Site'
    )
    scan_runs_count = tables.Column(
        accessor='scan_runs__count',
        verbose_name='Runs',
        orderable=False
    )

    class Meta(NetBoxTable.Meta):
        model = Scanner
        fields = (
            'pk', 'id', 'name', 'scanner_type', 'status', 'site',
            'cidr_range', 'target_hostname', 'description',
            'scan_runs_count', 'created', 'last_updated', 'actions'
        )
        default_columns = (
            'pk', 'name', 'scanner_type', 'status', 'site', 'scan_runs_count'
        )


class ScanRunTable(NetBoxTable):
    """Table for displaying ScanRun objects."""

    scanner = tables.Column(
        linkify=True,
        verbose_name='Scanner'
    )
    status = ChoiceFieldColumn(
        verbose_name='Status'
    )
    started_at = tables.DateTimeColumn(
        verbose_name='Started',
        format='Y-m-d H:i:s'
    )
    completed_at = tables.DateTimeColumn(
        verbose_name='Completed',
        format='Y-m-d H:i:s'
    )
    ips_discovered = tables.Column(
        verbose_name='IPs'
    )
    devices_discovered = tables.Column(
        verbose_name='Devices'
    )

    class Meta(NetBoxTable.Meta):
        model = ScanRun
        fields = (
            'pk', 'id', 'scanner', 'status', 'started_at', 'completed_at',
            'ips_discovered', 'devices_discovered', 'interfaces_discovered',
            'vlans_discovered', 'created', 'actions'
        )
        default_columns = (
            'pk', 'scanner', 'status', 'started_at', 'completed_at',
            'ips_discovered', 'devices_discovered'
        )


class DiscoveredDeviceTable(NetBoxTable):
    """Table for displaying DiscoveredDevice objects."""

    scan_run = tables.Column(
        linkify=True,
        verbose_name='Scan Run'
    )
    device = tables.Column(
        linkify=True,
        verbose_name='Device'
    )
    action = tables.Column(
        verbose_name='Action'
    )

    class Meta(NetBoxTable.Meta):
        model = DiscoveredDevice
        fields = (
            'pk', 'id', 'scan_run', 'device', 'action', 'created', 'actions'
        )
        default_columns = (
            'pk', 'scan_run', 'device', 'action', 'created'
        )
        # Audit records are read-only - exclude edit action
        exclude_actions = ('edit',)


class DiscoveredIPAddressTable(NetBoxTable):
    """Table for displaying DiscoveredIPAddress objects."""

    scan_run = tables.Column(
        linkify=True,
        verbose_name='Scan Run'
    )
    ip_address = tables.Column(
        linkify=True,
        verbose_name='IP Address'
    )
    hostname = tables.Column(
        verbose_name='Hostname'
    )
    action = tables.Column(
        verbose_name='Action'
    )

    class Meta(NetBoxTable.Meta):
        model = DiscoveredIPAddress
        fields = (
            'pk', 'id', 'scan_run', 'ip_address', 'hostname', 'action',
            'open_ports', 'created', 'actions'
        )
        default_columns = (
            'pk', 'scan_run', 'ip_address', 'hostname', 'action', 'created'
        )
        # Audit records are read-only - exclude edit action
        exclude_actions = ('edit',)
