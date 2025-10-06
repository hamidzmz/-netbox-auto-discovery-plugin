"""API serializers for Auto Discovery Plugin."""

from rest_framework import serializers
from netbox.api.serializers import NetBoxModelSerializer
from dcim.api.serializers import SiteSerializer

from netbox_netbox_auto_discovery_plugin.models import (
    Scanner,
    ScanRun,
    DiscoveredDevice,
    DiscoveredIPAddress,
)


class ScannerSerializer(NetBoxModelSerializer):
    """Serializer for Scanner model."""

    url = serializers.HyperlinkedIdentityField(
        view_name='plugins-api:netbox_netbox_auto_discovery_plugin-api:scanner-detail'
    )
    site = SiteSerializer(nested=True, required=False, allow_null=True)

    class Meta:
        model = Scanner
        fields = [
            'id', 'url', 'display', 'name', 'scanner_type', 'status', 'description',
            'cidr_range', 'target_hostname', 'connection_protocol',
            'ssh_username', 'ssh_port', 'snmp_port', 'scan_interval_hours',
            'site', 'tags', 'custom_fields', 'created', 'last_updated',
        ]
        brief_fields = ['id', 'url', 'display', 'name', 'scanner_type']


class ScanRunSerializer(NetBoxModelSerializer):
    """Serializer for ScanRun model."""

    url = serializers.HyperlinkedIdentityField(
        view_name='plugins-api:netbox_netbox_auto_discovery_plugin-api:scanrun-detail'
    )
    scanner = ScannerSerializer(nested=True)

    class Meta:
        model = ScanRun
        fields = [
            'id', 'url', 'display', 'scanner', 'status', 'started_at', 'completed_at',
            'ips_discovered', 'devices_discovered', 'interfaces_discovered', 'vlans_discovered',
            'log_output', 'error_message', 'job_id',
            'tags', 'custom_fields', 'created', 'last_updated',
        ]
        brief_fields = ['id', 'url', 'display', 'scanner', 'status']


class DiscoveredDeviceSerializer(NetBoxModelSerializer):
    """Serializer for DiscoveredDevice model."""

    url = serializers.HyperlinkedIdentityField(
        view_name='plugins-api:netbox_netbox_auto_discovery_plugin-api:discovereddevice-detail'
    )
    scan_run = ScanRunSerializer(nested=True)

    class Meta:
        model = DiscoveredDevice
        fields = [
            'id', 'url', 'display', 'scan_run', 'device', 'action', 'discovered_data',
            'tags', 'custom_fields', 'created', 'last_updated',
        ]
        brief_fields = ['id', 'url', 'display', 'device', 'action']


class DiscoveredIPAddressSerializer(NetBoxModelSerializer):
    """Serializer for DiscoveredIPAddress model."""

    url = serializers.HyperlinkedIdentityField(
        view_name='plugins-api:netbox_netbox_auto_discovery_plugin-api:discoveredipaddress-detail'
    )
    scan_run = ScanRunSerializer(nested=True)

    class Meta:
        model = DiscoveredIPAddress
        fields = [
            'id', 'url', 'display', 'scan_run', 'ip_address', 'action',
            'hostname', 'open_ports', 'services',
            'tags', 'custom_fields', 'created', 'last_updated',
        ]
        brief_fields = ['id', 'url', 'display', 'ip_address', 'action']
