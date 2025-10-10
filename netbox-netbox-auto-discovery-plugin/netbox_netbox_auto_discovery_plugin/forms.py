from django import forms
from django.core.exceptions import ValidationError
from dcim.models import Site
from netbox.forms import NetBoxModelForm, NetBoxModelFilterSetForm, NetBoxModelBulkEditForm
from utilities.forms.fields import (
    CommentField,
    DynamicModelChoiceField,
    TagFilterField,
)
from utilities.forms.rendering import FieldSet
import ipaddress

from .choices import (
    ScannerTypeChoices,
    ScannerStatusChoices,
    ScanRunStatusChoices,
    ConnectionProtocolChoices,
)
from .models import Scanner, ScanRun, DiscoveredDevice, DiscoveredIPAddress


class ScannerForm(NetBoxModelForm):

    site = DynamicModelChoiceField(
        queryset=Site.objects.all(),
        required=False,
        help_text="Associate discovered resources with this site"
    )

    comments = CommentField()

    fieldsets = (
        FieldSet('name', 'scanner_type', 'status', 'site', 'description', name='Basic Information'),
        FieldSet('cidr_range', name='Network Range Scan'),
        FieldSet(
            'target_hostname', 'connection_protocol',
            name='Cisco Switch Scan - Target'
        ),
        FieldSet(
            'ssh_username', 'ssh_password', 'ssh_port',
            name='SSH Credentials'
        ),
        FieldSet(
            'snmp_community', 'snmp_port',
            name='SNMP v2c Credentials'
        ),
        FieldSet(
            'snmp_v3_username', 'snmp_v3_auth_protocol', 'snmp_v3_auth_key',
            'snmp_v3_priv_protocol', 'snmp_v3_priv_key',
            name='SNMP v3 Credentials'
        ),
        FieldSet('scan_interval_hours', name='Automation'),
        FieldSet('tags', name='Tags'),
    )

    def clean_cidr_range(self):
        cidr_range = self.cleaned_data.get('cidr_range')
        if cidr_range:
            try:
                network = ipaddress.ip_network(cidr_range, strict=False)
                if network.num_addresses > 16777216:
                    raise ValidationError(
                        f'CIDR range is too large ({network.num_addresses:,} addresses). '
                        f'Consider scanning smaller subnets to avoid timeouts.'
                    )
            except ValueError:
                raise ValidationError(
                    f'Invalid CIDR notation: "{cidr_range}". '
                    f'Expected format like 192.168.1.0/24 or 10.0.0.0/16'
                )
        return cidr_range

    def clean(self):
        cleaned_data = super().clean()
        if not cleaned_data:
            return cleaned_data
        
        scanner_type = cleaned_data.get('scanner_type')
        cidr_range = cleaned_data.get('cidr_range')
        target_hostname = cleaned_data.get('target_hostname')
        connection_protocol = cleaned_data.get('connection_protocol')
        ssh_username = cleaned_data.get('ssh_username')
        ssh_password = cleaned_data.get('ssh_password')
        snmp_community = cleaned_data.get('snmp_community')
        snmp_v3_username = cleaned_data.get('snmp_v3_username')

        if scanner_type == ScannerTypeChoices.TYPE_NETWORK_RANGE:
            if not cidr_range:
                self.add_error('cidr_range', 'This field is required for network range scans.')

        elif scanner_type == ScannerTypeChoices.TYPE_CISCO_SWITCH:
            if not target_hostname:
                self.add_error('target_hostname', 'This field is required for Cisco switch scans.')

            if not connection_protocol:
                self.add_error('connection_protocol', 'This field is required for Cisco switch scans.')

            if connection_protocol == ConnectionProtocolChoices.PROTOCOL_SSH:
                if not ssh_username:
                    self.add_error('ssh_username', 'Username is required for SSH connections.')
                if not ssh_password:
                    self.add_error('ssh_password', 'Password is required for SSH connections.')

            elif connection_protocol == ConnectionProtocolChoices.PROTOCOL_SNMP_V2C:
                if not snmp_community:
                    self.add_error('snmp_community', 'Community string is required for SNMP v2c.')

            elif connection_protocol == ConnectionProtocolChoices.PROTOCOL_SNMP_V3:
                if not snmp_v3_username:
                    self.add_error('snmp_v3_username', 'Username is required for SNMP v3.')
                
                snmp_v3_auth_protocol = cleaned_data.get('snmp_v3_auth_protocol')
                snmp_v3_auth_key = cleaned_data.get('snmp_v3_auth_key')
                snmp_v3_priv_protocol = cleaned_data.get('snmp_v3_priv_protocol')
                snmp_v3_priv_key = cleaned_data.get('snmp_v3_priv_key')
                
                if not snmp_v3_auth_protocol:
                    self.add_error('snmp_v3_auth_protocol', 'Authentication protocol is required for SNMP v3.')
                elif snmp_v3_auth_protocol.upper() not in ['MD5', 'SHA', 'SHA1']:
                    self.add_error('snmp_v3_auth_protocol', 'Must be MD5, SHA, or SHA1.')
                
                if not snmp_v3_auth_key:
                    self.add_error('snmp_v3_auth_key', 'Authentication key is required for SNMP v3.')
                
                if snmp_v3_priv_protocol and not snmp_v3_priv_key:
                    self.add_error('snmp_v3_priv_key', 'Privacy key is required when privacy protocol is specified.')
                
                if snmp_v3_priv_protocol and snmp_v3_priv_protocol.upper() not in ['DES', 'AES', 'AES128']:
                    self.add_error('snmp_v3_priv_protocol', 'Must be DES, AES, or AES128.')

        return cleaned_data

    class Meta:
        model = Scanner
        fields = (
            'name', 'scanner_type', 'status', 'site', 'description',
            'cidr_range', 'target_hostname', 'connection_protocol',
            'ssh_username', 'ssh_password', 'ssh_port',
            'snmp_community', 'snmp_port',
            'snmp_v3_username', 'snmp_v3_auth_protocol', 'snmp_v3_auth_key',
            'snmp_v3_priv_protocol', 'snmp_v3_priv_key',
            'scan_interval_hours', 'tags', 'comments'
        )
        widgets = {
            'ssh_password': forms.PasswordInput(render_value=True),
            'snmp_community': forms.PasswordInput(render_value=True),
            'snmp_v3_auth_key': forms.PasswordInput(render_value=True),
            'snmp_v3_priv_key': forms.PasswordInput(render_value=True),
        }


class ScannerFilterForm(NetBoxModelFilterSetForm):

    model = Scanner

    scanner_type = forms.MultipleChoiceField(
        choices=ScannerTypeChoices,
        required=False,
        label='Scanner Type'
    )

    status = forms.MultipleChoiceField(
        choices=ScannerStatusChoices,
        required=False,
        label='Status'
    )

    site_id = DynamicModelChoiceField(
        queryset=Site.objects.all(),
        required=False,
        label='Site'
    )

    tag = TagFilterField(model)


class ScannerBulkEditForm(NetBoxModelBulkEditForm):

    model = Scanner

    status = forms.ChoiceField(
        choices=ScannerStatusChoices,
        required=False
    )

    site = DynamicModelChoiceField(
        queryset=Site.objects.all(),
        required=False
    )

    description = forms.CharField(
        max_length=500,
        required=False
    )

    nullable_fields = ('site', 'description', 'scan_interval_hours')


class ScanRunForm(NetBoxModelForm):

    comments = CommentField()

    class Meta:
        model = ScanRun
        fields = ('scanner', 'status', 'comments', 'tags')


class ScanRunFilterForm(NetBoxModelFilterSetForm):

    model = ScanRun

    status = forms.MultipleChoiceField(
        choices=ScanRunStatusChoices,
        required=False,
        label='Status'
    )

    tag = TagFilterField(model)


class DiscoveredDeviceFilterForm(NetBoxModelFilterSetForm):

    model = DiscoveredDevice
    tag = TagFilterField(model)


class DiscoveredIPAddressFilterForm(NetBoxModelFilterSetForm):

    model = DiscoveredIPAddress
    tag = TagFilterField(model)


class DiscoveredDeviceForm(NetBoxModelForm):

    comments = CommentField()

    class Meta:
        model = DiscoveredDevice
        fields = ('scan_run', 'device', 'action', 'discovered_data', 'comments', 'tags')


class DiscoveredIPAddressForm(NetBoxModelForm):

    comments = CommentField()

    class Meta:
        model = DiscoveredIPAddress
        fields = ('scan_run', 'ip_address', 'action', 'hostname', 'open_ports', 'services', 'comments', 'tags')
