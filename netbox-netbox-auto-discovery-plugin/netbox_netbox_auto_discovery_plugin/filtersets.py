import django_filters
from netbox.filtersets import NetBoxModelFilterSet
from dcim.models import Site

from .choices import ScannerTypeChoices, ScannerStatusChoices, ScanRunStatusChoices
from .models import Scanner, ScanRun, DiscoveredDevice, DiscoveredIPAddress


class ScannerFilterSet(NetBoxModelFilterSet):

    scanner_type = django_filters.MultipleChoiceFilter(
        choices=ScannerTypeChoices,
        null_value=None
    )

    status = django_filters.MultipleChoiceFilter(
        choices=ScannerStatusChoices,
        null_value=None
    )

    site_id = django_filters.ModelMultipleChoiceFilter(
        queryset=Site.objects.all(),
        label='Site (ID)',
    )

    class Meta:
        model = Scanner
        fields = ['id', 'name', 'scanner_type', 'status', 'site']

    def search(self, queryset, name, value):
        return queryset.filter(
            django_filters.Q(name__icontains=value) |
            django_filters.Q(description__icontains=value) |
            django_filters.Q(cidr_range__icontains=value) |
            django_filters.Q(target_hostname__icontains=value)
        )


class ScanRunFilterSet(NetBoxModelFilterSet):

    status = django_filters.MultipleChoiceFilter(
        choices=ScanRunStatusChoices,
        null_value=None
    )

    scanner_id = django_filters.ModelMultipleChoiceFilter(
        queryset=Scanner.objects.all(),
        label='Scanner (ID)',
    )

    class Meta:
        model = ScanRun
        fields = ['id', 'scanner', 'status']

    def search(self, queryset, name, value):
        return queryset.filter(
            django_filters.Q(scanner__name__icontains=value) |
            django_filters.Q(log_output__icontains=value) |
            django_filters.Q(error_message__icontains=value)
        )


class DiscoveredDeviceFilterSet(NetBoxModelFilterSet):

    action = django_filters.ChoiceFilter(
        choices=[('created', 'Created'), ('updated', 'Updated')]
    )

    scan_run_id = django_filters.ModelMultipleChoiceFilter(
        queryset=ScanRun.objects.all(),
        label='Scan Run (ID)',
    )

    class Meta:
        model = DiscoveredDevice
        fields = ['id', 'scan_run', 'device', 'action']

    def search(self, queryset, name, value):
        return queryset.filter(
            django_filters.Q(device__name__icontains=value)
        )


class DiscoveredIPAddressFilterSet(NetBoxModelFilterSet):

    action = django_filters.ChoiceFilter(
        choices=[('created', 'Created'), ('updated', 'Updated')]
    )

    scan_run_id = django_filters.ModelMultipleChoiceFilter(
        queryset=ScanRun.objects.all(),
        label='Scan Run (ID)',
    )

    class Meta:
        model = DiscoveredIPAddress
        fields = ['id', 'scan_run', 'ip_address', 'action', 'hostname']

    def search(self, queryset, name, value):
        return queryset.filter(
            django_filters.Q(ip_address__address__icontains=value) |
            django_filters.Q(hostname__icontains=value)
        )
