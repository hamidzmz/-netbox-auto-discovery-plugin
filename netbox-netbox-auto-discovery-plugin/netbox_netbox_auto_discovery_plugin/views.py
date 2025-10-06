"""Django views for Auto Discovery Plugin."""

from django.contrib import messages
from django.db.models import Count, Q
from django.shortcuts import get_object_or_404, redirect, render
from django.views import View

from netbox.views import generic
from utilities.views import ViewTab, register_model_view
from core.models import Job as CoreJob

from . import filtersets, forms, models, tables
from .jobs import NetworkRangeScanJob, CiscoSwitchScanJob
from .choices import ScannerTypeChoices


#
# Scanner views
#

class ScannerView(generic.ObjectView):
    """Detail view for a Scanner."""
    queryset = models.Scanner.objects.all()
    template_name = 'netbox_netbox_auto_discovery_plugin/scanner_detail.html'

    def get_extra_context(self, request, instance):
        """Add computed statistics to template context."""
        from .choices import ScanRunStatusChoices
        context = super().get_extra_context(request, instance)
        context['completed_runs_count'] = instance.scan_runs.filter(
            status=ScanRunStatusChoices.STATUS_COMPLETED
        ).count()
        context['failed_runs_count'] = instance.scan_runs.filter(
            status=ScanRunStatusChoices.STATUS_FAILED
        ).count()
        return context


class ScannerListView(generic.ObjectListView):
    """List view for Scanners."""
    queryset = models.Scanner.objects.annotate(
        scan_runs_count=Count('scan_runs')
    )
    table = tables.ScannerTable
    filterset = filtersets.ScannerFilterSet
    filterset_form = forms.ScannerFilterForm


class ScannerEditView(generic.ObjectEditView):
    """Edit view for a Scanner."""
    queryset = models.Scanner.objects.all()
    form = forms.ScannerForm


class ScannerDeleteView(generic.ObjectDeleteView):
    """Delete view for a Scanner."""
    queryset = models.Scanner.objects.all()


class ScannerBulkImportView(generic.BulkImportView):
    """Bulk import view for Scanners."""
    queryset = models.Scanner.objects.all()
    model_form = forms.ScannerForm


class ScannerBulkEditView(generic.BulkEditView):
    """Bulk edit view for Scanners."""
    queryset = models.Scanner.objects.all()
    filterset = filtersets.ScannerFilterSet
    table = tables.ScannerTable
    form = forms.ScannerBulkEditForm


class ScannerBulkDeleteView(generic.BulkDeleteView):
    """Bulk delete view for Scanners."""
    queryset = models.Scanner.objects.all()
    filterset = filtersets.ScannerFilterSet
    table = tables.ScannerTable


class ScannerRunView(View):
    """View to execute a scanner (enqueue background job)."""

    def post(self, request, pk):
        """Handle POST request to run a scan."""
        scanner = get_object_or_404(models.Scanner, pk=pk)

        try:
            # Select appropriate job based on scanner type
            if scanner.scanner_type == ScannerTypeChoices.TYPE_NETWORK_RANGE:
                job_class = NetworkRangeScanJob
            elif scanner.scanner_type == ScannerTypeChoices.TYPE_CISCO_SWITCH:
                job_class = CiscoSwitchScanJob
            else:
                messages.error(request, f"Unknown scanner type: {scanner.scanner_type}")
                return redirect('plugins:netbox_netbox_auto_discovery_plugin:scanner', pk=pk)

            # Enqueue the job
            job_result = job_class.enqueue(
                user=request.user,
                scanner_id=scanner.pk
            )

            messages.success(
                request,
                f"Scan job enqueued successfully. Job ID: {job_result.pk}"
            )

        except Exception as e:
            messages.error(
                request,
                f"Failed to enqueue scan job: {str(e)}"
            )

        return redirect('plugins:netbox_netbox_auto_discovery_plugin:scanner', pk=pk)


#
# ScanRun views
#

class ScanRunView(generic.ObjectView):
    """Detail view for a ScanRun."""
    queryset = models.ScanRun.objects.select_related('scanner')
    template_name = 'netbox_netbox_auto_discovery_plugin/scanrun_detail.html'


class ScanRunListView(generic.ObjectListView):
    """List view for ScanRuns."""
    queryset = models.ScanRun.objects.select_related('scanner')
    table = tables.ScanRunTable
    filterset = filtersets.ScanRunFilterSet
    filterset_form = forms.ScanRunFilterForm


class ScanRunEditView(generic.ObjectEditView):
    """Edit view for a ScanRun (limited fields)."""
    queryset = models.ScanRun.objects.all()
    form = forms.ScanRunForm


class ScanRunDeleteView(generic.ObjectDeleteView):
    """Delete view for a ScanRun."""
    queryset = models.ScanRun.objects.all()


class ScanRunBulkDeleteView(generic.BulkDeleteView):
    """Bulk delete view for ScanRuns."""
    queryset = models.ScanRun.objects.all()
    filterset = filtersets.ScanRunFilterSet
    table = tables.ScanRunTable


#
# DiscoveredDevice views
#

class DiscoveredDeviceView(generic.ObjectView):
    """Detail view for a DiscoveredDevice."""
    queryset = models.DiscoveredDevice.objects.select_related('scan_run', 'device')

    def get_extra_context(self, request, instance):
        return {
            'actions': ['delete']  # Exclude edit action for audit records
        }


class DiscoveredDeviceListView(generic.ObjectListView):
    """List view for DiscoveredDevices."""
    queryset = models.DiscoveredDevice.objects.select_related('scan_run', 'device')
    table = tables.DiscoveredDeviceTable
    filterset = filtersets.DiscoveredDeviceFilterSet
    filterset_form = forms.DiscoveredDeviceFilterForm


class DiscoveredDeviceEditView(generic.ObjectEditView):
    """Edit view for a DiscoveredDevice (read-only audit records)."""
    queryset = models.DiscoveredDevice.objects.all()
    form = forms.DiscoveredDeviceForm


class DiscoveredDeviceDeleteView(generic.ObjectDeleteView):
    """Delete view for a DiscoveredDevice."""
    queryset = models.DiscoveredDevice.objects.all()


class DiscoveredDeviceBulkDeleteView(generic.BulkDeleteView):
    """Bulk delete view for DiscoveredDevices."""
    queryset = models.DiscoveredDevice.objects.all()
    table = tables.DiscoveredDeviceTable


#
# DiscoveredIPAddress views
#

class DiscoveredIPAddressView(generic.ObjectView):
    """Detail view for a DiscoveredIPAddress."""
    queryset = models.DiscoveredIPAddress.objects.select_related('scan_run', 'ip_address')

    def get_extra_context(self, request, instance):
        return {
            'actions': ['delete']  # Exclude edit action for audit records
        }


class DiscoveredIPAddressListView(generic.ObjectListView):
    """List view for DiscoveredIPAddresses."""
    queryset = models.DiscoveredIPAddress.objects.select_related('scan_run', 'ip_address')
    table = tables.DiscoveredIPAddressTable
    filterset = filtersets.DiscoveredIPAddressFilterSet
    filterset_form = forms.DiscoveredIPAddressFilterForm


class DiscoveredIPAddressEditView(generic.ObjectEditView):
    """Edit view for a DiscoveredIPAddress (read-only audit records)."""
    queryset = models.DiscoveredIPAddress.objects.all()
    form = forms.DiscoveredIPAddressForm


class DiscoveredIPAddressDeleteView(generic.ObjectDeleteView):
    """Delete view for a DiscoveredIPAddress."""
    queryset = models.DiscoveredIPAddress.objects.all()


class DiscoveredIPAddressBulkDeleteView(generic.BulkDeleteView):
    """Bulk delete view for DiscoveredIPAddresses."""
    queryset = models.DiscoveredIPAddress.objects.all()
    table = tables.DiscoveredIPAddressTable
