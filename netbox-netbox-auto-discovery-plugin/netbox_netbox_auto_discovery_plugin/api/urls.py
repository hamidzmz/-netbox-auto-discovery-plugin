"""API URLs for Auto Discovery Plugin."""

from netbox.api.routers import NetBoxRouter
from . import views

router = NetBoxRouter()
router.register('scanners', views.ScannerViewSet)
router.register('scan-runs', views.ScanRunViewSet)
router.register('discovered-devices', views.DiscoveredDeviceViewSet)
router.register('discovered-ip-addresses', views.DiscoveredIPAddressViewSet)

urlpatterns = router.urls
