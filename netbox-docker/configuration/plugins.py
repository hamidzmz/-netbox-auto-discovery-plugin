# Add your plugins and plugin settings here.
# Of course uncomment this file out.

# To learn how to build images with your required plugins
# See https://github.com/netbox-community/netbox-docker/wiki/Using-Netbox-Plugins

# NetBox Auto Discovery Plugin Configuration
PLUGINS = [
    'netbox_netbox_auto_discovery_plugin',
]

PLUGINS_CONFIG = {
    'netbox_netbox_auto_discovery_plugin': {
        'scan_timeout_seconds': 3600,
        'max_concurrent_scans': 5,
    }
}
