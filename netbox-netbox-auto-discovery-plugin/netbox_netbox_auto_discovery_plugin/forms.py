"""Django forms for Auto Discovery Plugin."""

from django import forms
from dcim.models import Site
from netbox.forms import NetBoxModelForm, NetBoxModelFilterSetForm, NetBoxModelBulkEditForm
from utilities.forms.fields import (
    CommentField,
    DynamicModelChoiceField,
    TagFilterField,
)
from utilities.forms.rendering import FieldSet

from .choices import (
    ScannerTypeChoices,
    ScannerStatusChoices,
    ScanRunStatusChoices,
    ConnectionProtocolChoices,
)
from .models import Scanner, ScanRun, DiscoveredDevice, DiscoveredIPAddress


class ScannerForm(NetBoxModelForm):
    """Form for creating/editing Scanner objects."""

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
    """Filter form for Scanner list view."""

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
    """Bulk edit form for Scanner objects."""

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
    """Form for creating/editing ScanRun objects (mostly read-only, created by jobs)."""

    comments = CommentField()

    class Meta:
        model = ScanRun
        fields = ('scanner', 'status', 'comments', 'tags')
        # Most fields are auto-populated by the scan job


class ScanRunFilterForm(NetBoxModelFilterSetForm):
    """Filter form for ScanRun list view."""

    model = ScanRun

    status = forms.MultipleChoiceField(
        choices=ScanRunStatusChoices,
        required=False,
        label='Status'
    )

    tag = TagFilterField(model)


class DiscoveredDeviceFilterForm(NetBoxModelFilterSetForm):
    """Filter form for DiscoveredDevice list view."""

    model = DiscoveredDevice
    tag = TagFilterField(model)


class DiscoveredIPAddressFilterForm(NetBoxModelFilterSetForm):
    """Filter form for DiscoveredIPAddress list view."""

    model = DiscoveredIPAddress
    tag = TagFilterField(model)


class DiscoveredDeviceForm(NetBoxModelForm):
    """Form for editing DiscoveredDevice objects (audit records)."""

    comments = CommentField()

    class Meta:
        model = DiscoveredDevice
        fields = ('scan_run', 'device', 'action', 'discovered_data', 'comments', 'tags')
        # Note: These are audit records, typically not edited manually


class DiscoveredIPAddressForm(NetBoxModelForm):
    """Form for editing DiscoveredIPAddress objects (audit records)."""

    comments = CommentField()

    class Meta:
        model = DiscoveredIPAddress
        fields = ('scan_run', 'ip_address', 'action', 'hostname', 'open_ports', 'services', 'comments', 'tags')
        # Note: These are audit records, typically not edited manually
