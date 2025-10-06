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
    queryset = Scanner.objects.all()
    serializer_class = ScannerSerializer
    filterset_class = filtersets.ScannerFilterSet


class ScanRunViewSet(NetBoxModelViewSet):
    queryset = ScanRun.objects.all()
    serializer_class = ScanRunSerializer
    filterset_class = filtersets.ScanRunFilterSet


class DiscoveredDeviceViewSet(NetBoxModelViewSet):
    queryset = DiscoveredDevice.objects.all()
    serializer_class = DiscoveredDeviceSerializer
    filterset_class = filtersets.DiscoveredDeviceFilterSet


class DiscoveredIPAddressViewSet(NetBoxModelViewSet):
    queryset = DiscoveredIPAddress.objects.all()
    serializer_class = DiscoveredIPAddressSerializer
    filterset_class = filtersets.DiscoveredIPAddressFilterSet
