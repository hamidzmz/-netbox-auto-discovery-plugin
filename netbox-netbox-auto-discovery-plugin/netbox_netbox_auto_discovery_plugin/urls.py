"""URL patterns for Auto Discovery Plugin."""

from django.urls import path
from netbox.views.generic import ObjectChangeLogView

from . import models, views


urlpatterns = (
    # Scanner URLs
    path('scanners/', views.ScannerListView.as_view(), name='scanner_list'),
    path('scanners/add/', views.ScannerEditView.as_view(), name='scanner_add'),
    path('scanners/import/', views.ScannerBulkImportView.as_view(), name='scanner_import'),
    path('scanners/edit/', views.ScannerBulkEditView.as_view(), name='scanner_bulk_edit'),
    path('scanners/delete/', views.ScannerBulkDeleteView.as_view(), name='scanner_bulk_delete'),
    path('scanners/<int:pk>/', views.ScannerView.as_view(), name='scanner'),
    path('scanners/<int:pk>/edit/', views.ScannerEditView.as_view(), name='scanner_edit'),
    path('scanners/<int:pk>/delete/', views.ScannerDeleteView.as_view(), name='scanner_delete'),
    path('scanners/<int:pk>/run/', views.ScannerRunView.as_view(), name='scanner_run'),
    path(
        'scanners/<int:pk>/changelog/',
        ObjectChangeLogView.as_view(),
        name='scanner_changelog',
        kwargs={'model': models.Scanner},
    ),

    # ScanRun URLs
    path('scan-runs/', views.ScanRunListView.as_view(), name='scanrun_list'),
    path('scan-runs/add/', views.ScanRunEditView.as_view(), name='scanrun_add'),
    path('scan-runs/delete/', views.ScanRunBulkDeleteView.as_view(), name='scanrun_bulk_delete'),
    path('scan-runs/<int:pk>/', views.ScanRunView.as_view(), name='scanrun'),
    path('scan-runs/<int:pk>/edit/', views.ScanRunEditView.as_view(), name='scanrun_edit'),
    path('scan-runs/<int:pk>/delete/', views.ScanRunDeleteView.as_view(), name='scanrun_delete'),
    path(
        'scan-runs/<int:pk>/changelog/',
        ObjectChangeLogView.as_view(),
        name='scanrun_changelog',
        kwargs={'model': models.ScanRun},
    ),

    # DiscoveredDevice URLs
    path('discovered-devices/', views.DiscoveredDeviceListView.as_view(), name='discovereddevice_list'),
    path('discovered-devices/delete/', views.DiscoveredDeviceBulkDeleteView.as_view(), name='discovereddevice_bulk_delete'),
    path('discovered-devices/<int:pk>/', views.DiscoveredDeviceView.as_view(), name='discovereddevice'),
    path('discovered-devices/<int:pk>/edit/', views.DiscoveredDeviceEditView.as_view(), name='discovereddevice_edit'),
    path('discovered-devices/<int:pk>/delete/', views.DiscoveredDeviceDeleteView.as_view(), name='discovereddevice_delete'),
    path(
        'discovered-devices/<int:pk>/changelog/',
        ObjectChangeLogView.as_view(),
        name='discovereddevice_changelog',
        kwargs={'model': models.DiscoveredDevice},
    ),

    # DiscoveredIPAddress URLs
    path('discovered-ips/', views.DiscoveredIPAddressListView.as_view(), name='discoveredipaddress_list'),
    path('discovered-ips/delete/', views.DiscoveredIPAddressBulkDeleteView.as_view(), name='discoveredipaddress_bulk_delete'),
    path('discovered-ips/<int:pk>/', views.DiscoveredIPAddressView.as_view(), name='discoveredipaddress'),
    path('discovered-ips/<int:pk>/edit/', views.DiscoveredIPAddressEditView.as_view(), name='discoveredipaddress_edit'),
    path('discovered-ips/<int:pk>/delete/', views.DiscoveredIPAddressDeleteView.as_view(), name='discoveredipaddress_delete'),
    path(
        'discovered-ips/<int:pk>/changelog/',
        ObjectChangeLogView.as_view(),
        name='discoveredipaddress_changelog',
        kwargs={'model': models.DiscoveredIPAddress},
    ),
)
