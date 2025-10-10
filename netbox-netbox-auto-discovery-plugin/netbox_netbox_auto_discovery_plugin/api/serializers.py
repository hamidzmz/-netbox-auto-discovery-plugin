from rest_framework import serializers
from rest_framework.exceptions import ValidationError
from netbox.api.serializers import NetBoxModelSerializer
from dcim.api.serializers import SiteSerializer
import ipaddress

from netbox_netbox_auto_discovery_plugin.models import (
    Scanner,
    ScanRun,
    DiscoveredDevice,
    DiscoveredIPAddress,
)
from netbox_netbox_auto_discovery_plugin.choices import (
    ScannerTypeChoices,
    ConnectionProtocolChoices,
)


class ScannerSerializer(NetBoxModelSerializer):

    url = serializers.HyperlinkedIdentityField(
        view_name='plugins-api:netbox_netbox_auto_discovery_plugin-api:scanner-detail'
    )
    site = SiteSerializer(nested=True, required=False, allow_null=True)
    
    ssh_password = serializers.CharField(max_length=255, required=False, allow_blank=True, write_only=True)
    snmp_community = serializers.CharField(max_length=100, required=False, allow_blank=True, write_only=True)
    snmp_v3_auth_key = serializers.CharField(max_length=255, required=False, allow_blank=True, write_only=True)
    snmp_v3_priv_key = serializers.CharField(max_length=255, required=False, allow_blank=True, write_only=True)

    def validate_cidr_range(self, value):
        if value:
            try:
                network = ipaddress.ip_network(value, strict=False)
                if network.num_addresses > 16777216:
                    raise ValidationError(
                        f'CIDR range is too large ({network.num_addresses:,} addresses). '
                        f'Consider scanning smaller subnets.'
                    )
            except ValueError:
                raise ValidationError(
                    f'Invalid CIDR notation: "{value}". Expected format: 192.168.1.0/24'
                )
        return value

    def validate(self, data):
        scanner_type = data.get('scanner_type')
        cidr_range = data.get('cidr_range')
        target_hostname = data.get('target_hostname')
        connection_protocol = data.get('connection_protocol')
        ssh_username = data.get('ssh_username')
        ssh_password = data.get('ssh_password')
        snmp_community = data.get('snmp_community')
        snmp_v3_username = data.get('snmp_v3_username')

        if scanner_type == ScannerTypeChoices.TYPE_NETWORK_RANGE:
            if not cidr_range:
                raise ValidationError({
                    'cidr_range': 'This field is required for network range scanners.'
                })

        elif scanner_type == ScannerTypeChoices.TYPE_CISCO_SWITCH:
            if not target_hostname:
                raise ValidationError({
                    'target_hostname': 'This field is required for Cisco switch scanners.'
                })

            if not connection_protocol:
                raise ValidationError({
                    'connection_protocol': 'This field is required for Cisco switch scanners.'
                })

            if connection_protocol == ConnectionProtocolChoices.PROTOCOL_SSH:
                if not ssh_username:
                    raise ValidationError({
                        'ssh_username': 'Username is required for SSH connections.'
                    })
                if not ssh_password:
                    raise ValidationError({
                        'ssh_password': 'Password is required for SSH connections.'
                    })

            elif connection_protocol == ConnectionProtocolChoices.PROTOCOL_SNMP_V2C:
                if not snmp_community:
                    raise ValidationError({
                        'snmp_community': 'Community string is required for SNMP v2c.'
                    })

            elif connection_protocol == ConnectionProtocolChoices.PROTOCOL_SNMP_V3:
                snmp_v3_auth_protocol = data.get('snmp_v3_auth_protocol')
                snmp_v3_auth_key = data.get('snmp_v3_auth_key')
                snmp_v3_priv_protocol = data.get('snmp_v3_priv_protocol')
                snmp_v3_priv_key = data.get('snmp_v3_priv_key')
                
                if not snmp_v3_username:
                    raise ValidationError({
                        'snmp_v3_username': 'Username is required for SNMP v3.'
                    })
                
                if not snmp_v3_auth_protocol:
                    raise ValidationError({
                        'snmp_v3_auth_protocol': 'Authentication protocol is required for SNMP v3.'
                    })
                elif snmp_v3_auth_protocol.upper() not in ['MD5', 'SHA', 'SHA1']:
                    raise ValidationError({
                        'snmp_v3_auth_protocol': 'Must be MD5, SHA, or SHA1.'
                    })
                
                if not snmp_v3_auth_key:
                    raise ValidationError({
                        'snmp_v3_auth_key': 'Authentication key is required for SNMP v3.'
                    })
                
                if snmp_v3_priv_protocol and not snmp_v3_priv_key:
                    raise ValidationError({
                        'snmp_v3_priv_key': 'Privacy key is required when privacy protocol is specified.'
                    })
                
                if snmp_v3_priv_protocol and snmp_v3_priv_protocol.upper() not in ['DES', 'AES', 'AES128']:
                    raise ValidationError({
                        'snmp_v3_priv_protocol': 'Must be DES, AES, or AES128.'
                    })

        return data

    class Meta:
        model = Scanner
        fields = [
            'id', 'url', 'display', 'name', 'scanner_type', 'status', 'description',
            'cidr_range', 'target_hostname', 'connection_protocol',
            'ssh_username', 'ssh_password', 'ssh_port',
            'snmp_community', 'snmp_port',
            'snmp_v3_username', 'snmp_v3_auth_protocol', 'snmp_v3_auth_key',
            'snmp_v3_priv_protocol', 'snmp_v3_priv_key',
            'scan_interval_hours', 'site', 'tags', 'custom_fields', 'created', 'last_updated',
        ]
        brief_fields = ['id', 'url', 'display', 'name', 'scanner_type']


class ScanRunSerializer(NetBoxModelSerializer):

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
