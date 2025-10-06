"""Navigation menu configuration for Auto Discovery Plugin."""

from netbox.plugins import PluginMenuButton, PluginMenuItem, PluginMenu


# Scanner menu item with action buttons
scanner_buttons = [
    PluginMenuButton(
        link='plugins:netbox_netbox_auto_discovery_plugin:scanner_add',
        title='Add Scanner',
        icon_class='mdi mdi-plus-thick',
        permissions=['netbox_netbox_auto_discovery_plugin.add_scanner']
    ),
    PluginMenuButton(
        link='plugins:netbox_netbox_auto_discovery_plugin:scanner_import',
        title='Import Scanners',
        icon_class='mdi mdi-upload',
        permissions=['netbox_netbox_auto_discovery_plugin.add_scanner']
    ),
]

# Scan run menu item
scanrun_buttons = [
    PluginMenuButton(
        link='plugins:netbox_netbox_auto_discovery_plugin:scanrun_list',
        title='View All Runs',
        icon_class='mdi mdi-history',
        permissions=['netbox_netbox_auto_discovery_plugin.view_scanrun']
    ),
]

# Build the full menu
menu = PluginMenu(
    label='Auto Discovery',
    groups=(
        ('Scanners', (
            PluginMenuItem(
                link='plugins:netbox_netbox_auto_discovery_plugin:scanner_list',
                link_text='Scanners',
                permissions=['netbox_netbox_auto_discovery_plugin.view_scanner'],
                buttons=scanner_buttons
            ),
            PluginMenuItem(
                link='plugins:netbox_netbox_auto_discovery_plugin:scanrun_list',
                link_text='Scan Runs',
                permissions=['netbox_netbox_auto_discovery_plugin.view_scanrun'],
                buttons=scanrun_buttons
            ),
        )),
        ('Discovery Results', (
            PluginMenuItem(
                link='plugins:netbox_netbox_auto_discovery_plugin:discovereddevice_list',
                link_text='Discovered Devices',
                permissions=['netbox_netbox_auto_discovery_plugin.view_discovereddevice']
            ),
            PluginMenuItem(
                link='plugins:netbox_netbox_auto_discovery_plugin:discoveredipaddress_list',
                link_text='Discovered IP Addresses',
                permissions=['netbox_netbox_auto_discovery_plugin.view_discoveredipaddress']
            ),
        )),
    ),
    icon_class='mdi mdi-radar'
)
