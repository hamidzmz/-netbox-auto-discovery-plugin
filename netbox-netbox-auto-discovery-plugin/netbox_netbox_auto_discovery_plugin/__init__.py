"""Top-level package for NetBox Auto Discovery Plugin."""

__author__ = """Hamid Zamani"""
__email__ = "hamidzamani445@gmail.com"
__version__ = "0.1.0"


from netbox.plugins import PluginConfig


class AutoDiscoveryConfig(PluginConfig):
    name = "netbox_netbox_auto_discovery_plugin"
    verbose_name = "NetBox Auto Discovery"
    description = "Automatically discover and inventory network resources via Network Range and Cisco Switch scans"
    version = __version__
    author = __author__
    author_email = __email__
    base_url = "auto-discovery"
    min_version = "4.0.0"
    max_version = "4.9.99"
    default_settings = {
        'scan_timeout_seconds': 3600,
        'max_concurrent_scans': 5,
    }


config = AutoDiscoveryConfig
