# Migration Guide

This document explains how to create and apply database migrations for the NetBox Auto Discovery Plugin.

## Prerequisites

- NetBox-docker environment running
- Plugin installed in editable mode
- NetBox `DEVELOPER` mode enabled

## Enable Developer Mode

In your NetBox-docker `configuration/configuration.py`, add:

```python
DEVELOPER = True
```

Then restart NetBox:

```bash
docker-compose restart netbox
```

## Create Migrations

From within the NetBox container:

```bash
# Enter the NetBox container
docker-compose exec netbox bash

# Create migrations for the plugin
cd /opt/netbox/netbox
python manage.py makemigrations netbox_netbox_auto_discovery_plugin

# Review the generated migration file
ls -la /path/to/plugin/netbox_netbox_auto_discovery_plugin/migrations/
```

## Apply Migrations

```bash
# Still inside NetBox container
python manage.py migrate netbox_netbox_auto_discovery_plugin

# Verify tables were created
python manage.py dbshell
\dt netbox_netbox_auto_discovery_plugin_*
\q
```

## Expected Tables

After migration, you should see:

- `netbox_netbox_auto_discovery_plugin_scanner`
- `netbox_netbox_auto_discovery_plugin_scanrun`
- `netbox_netbox_auto_discovery_plugin_discovereddevice`
- `netbox_netbox_auto_discovery_plugin_discoveredipaddress`

Plus standard NetBox model extensions (tags, custom fields, etc.)

## Rollback Migrations

If needed, roll back:

```bash
# Show migration history
python manage.py showmigrations netbox_netbox_auto_discovery_plugin

# Roll back to previous state
python manage.py migrate netbox_netbox_auto_discovery_plugin <migration_name>

# Or completely unapply
python manage.py migrate netbox_netbox_auto_discovery_plugin zero
```

## Troubleshooting

### Import Errors During Migration

If you see import errors for `utilities.choices` or `netbox.models`:
- Ensure the plugin is installed in the NetBox environment
- Verify `PLUGINS` list in `configuration.py` includes the plugin
- Restart NetBox after changes

### Missing Fields

If fields are missing after migration:
- Check model definitions in `models.py`
- Re-run `makemigrations` to capture new fields
- Apply new migration with `migrate`

### Permission Errors

Ensure the database user has CREATE TABLE privileges.

## Next Steps

After successful migration:
1. Test scanner creation via Django admin or API
2. Verify foreign key relationships work (Scanner → Site)
3. Create test scan runs
4. Check change logging functionality
