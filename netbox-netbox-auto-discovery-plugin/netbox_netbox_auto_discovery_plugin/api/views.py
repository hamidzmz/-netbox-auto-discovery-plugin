"""API views for Auto Discovery Plugin."""

from netbox.api.viewsets import NetBoxModelViewSet

from netbox_netbox_auto_discovery_plugin import filtersets
from netbox_netbox_auto_discovery_plugin.models import (
    Scanner,
    ScanRun,
    DiscoveredDevice,
    DiscoveredIPAddress,
)
from .serializers import (
    ScannerSerializer,
    ScanRunSerializer,
    DiscoveredDeviceSerializer,
    DiscoveredIPAddressSerializer,
)


class ScannerViewSet(NetBoxModelViewSet):
    """API viewset for Scanner model."""
    queryset = Scanner.objects.all()
    serializer_class = ScannerSerializer
    filterset_class = filtersets.ScannerFilterSet


class ScanRunViewSet(NetBoxModelViewSet):
    """API viewset for ScanRun model."""
    queryset = ScanRun.objects.all()
    serializer_class = ScanRunSerializer
    filterset_class = filtersets.ScanRunFilterSet


class DiscoveredDeviceViewSet(NetBoxModelViewSet):
    """API viewset for DiscoveredDevice model."""
    queryset = DiscoveredDevice.objects.all()
    serializer_class = DiscoveredDeviceSerializer
    filterset_class = filtersets.DiscoveredDeviceFilterSet


class DiscoveredIPAddressViewSet(NetBoxModelViewSet):
    """API viewset for DiscoveredIPAddress model."""
    queryset = DiscoveredIPAddress.objects.all()
    serializer_class = DiscoveredIPAddressSerializer
    filterset_class = filtersets.DiscoveredIPAddressFilterSet
