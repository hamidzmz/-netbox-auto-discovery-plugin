# Installing the Plugin in netbox-docker

This guide shows you how to install the NetBox Auto Discovery Plugin in your netbox-docker installation.

## Directory Structure

```
/home/hamidzmz/NetboxPr/
├── netbox-docker/              # Your NetBox Docker installation
└── netbox-netbox-auto-discovery-plugin/  # This plugin
```

## Method 1: Install via Local Path (Development)

This method is best for **development and testing** as it allows you to edit the plugin code and see changes immediately.

### Step 1: Create `plugin_requirements.txt`

In your netbox-docker directory, create a file called `plugin_requirements.txt`:

```bash
cd /home/hamidzmz/NetboxPr/netbox-docker
cat > plugin_requirements.txt << 'EOF'
# Install local plugin in editable mode
-e /plugin/netbox-netbox-auto-discovery-plugin
EOF
```

### Step 2: Update `docker-compose.override.yml`

Edit `/home/hamidzmz/NetboxPr/netbox-docker/docker-compose.override.yml`:

```yaml
services:
  netbox:
    ports:
      - "127.0.0.1:8000:8080"
    volumes:
      # Mount the plugin directory into the container
      - /home/hamidzmz/NetboxPr/netbox-netbox-auto-discovery-plugin:/plugin/netbox-netbox-auto-discovery-plugin:ro
    environment:
      # Enable developer mode for migrations
      DEVELOPER: "true"

  netbox-worker:
    volumes:
      # Also mount for the worker
      - /home/hamidzmz/NetboxPr/netbox-netbox-auto-discovery-plugin:/plugin/netbox-netbox-auto-discovery-plugin:ro
    environment:
      DEVELOPER: "true"

  netbox-housekeeping:
    volumes:
      # Also mount for housekeeping
      - /home/hamidzmz/NetboxPr/netbox-netbox-auto-discovery-plugin:/plugin/netbox-netbox-auto-discovery-plugin:ro
    environment:
      DEVELOPER: "true"
```

### Step 3: Configure the Plugin

Edit `/home/hamidzmz/NetboxPr/netbox-docker/configuration/plugins.py`:

```python
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
```

### Step 4: Rebuild and Restart

```bash
cd /home/hamidzmz/NetboxPr/netbox-docker

# Stop existing containers
docker compose down

# Rebuild the netbox image with plugins
docker compose build --no-cache netbox

# Start all services
docker compose up -d

# Wait for services to be healthy
docker compose ps
```

### Step 5: Run Migrations

```bash
# Enter the netbox container
docker compose exec netbox bash

# Inside the container, run migrations
cd /opt/netbox/netbox
python manage.py migrate netbox_netbox_auto_discovery_plugin

# Collect static files (if needed)
python manage.py collectstatic --no-input

# Exit container
exit
```

### Step 6: Create Superuser (if needed)

```bash
docker compose exec netbox /opt/netbox/netbox/manage.py createsuperuser
```

### Step 7: Verify Installation

1. Open http://127.0.0.1:8000 in your browser
2. Log in with your superuser credentials
3. Look for **"Auto Discovery"** in the main navigation menu
4. You should see:
   - Scanners submenu
   - Scan Runs submenu
   - Discovery Results submenu

---

## Method 2: Install via Git URL (Production)

This method is best for **production** as it installs a specific version.

### Step 1: Create `plugin_requirements.txt`

```bash
cd /home/hamidzmz/NetboxPr/netbox-docker
cat > plugin_requirements.txt << 'EOF'
# Install from Git repository
git+https://github.com/hamidzmz/netbox-netbox-auto-discovery-plugin.git@main
EOF
```

### Step 2: Configure Plugin (same as Method 1, Step 3)

Edit `/home/hamidzmz/NetboxPr/netbox-docker/configuration/plugins.py` as shown above.

### Step 3: Rebuild and Run

```bash
docker compose down
docker compose build --no-cache netbox
docker compose up -d
docker compose exec netbox python manage.py migrate netbox_netbox_auto_discovery_plugin
```

---

## Method 3: Build Custom Dockerfile (Advanced)

For a completely custom build, create a `Dockerfile-Plugins`:

```dockerfile
# Dockerfile-Plugins
FROM netboxcommunity/netbox:latest

# Copy plugin requirements
COPY plugin_requirements.txt /tmp/

# Install plugins
RUN /opt/netbox/venv/bin/pip install --no-cache-dir -r /tmp/plugin_requirements.txt

# Collect static files
RUN /opt/netbox/venv/bin/python /opt/netbox/netbox/manage.py collectstatic --no-input
```

Then update `docker-compose.override.yml`:

```yaml
services:
  netbox:
    build:
      context: .
      dockerfile: Dockerfile-Plugins
    image: netbox:latest-plugins
    ports:
      - "127.0.0.1:8000:8080"

  netbox-worker:
    image: netbox:latest-plugins

  netbox-housekeeping:
    image: netbox:latest-plugins
```

---

## Troubleshooting

### Plugin Not Found

**Error**: `ModuleNotFoundError: No module named 'netbox_netbox_auto_discovery_plugin'`

**Solution**:
```bash
# Check if plugin is installed
docker compose exec netbox /opt/netbox/venv/bin/pip list | grep netbox-netbox-auto-discovery

# If not listed, reinstall
docker compose exec netbox /opt/netbox/venv/bin/pip install -e /plugin/netbox-netbox-auto-discovery-plugin
```

### Import Errors

**Error**: `ImportError: cannot import name 'NetBoxModel'`

**Solution**: This is a NetBox version mismatch. Ensure you're using NetBox 4.0+:
```bash
docker compose exec netbox /opt/netbox/venv/bin/python -c "import netbox; print(netbox.VERSION)"
```

### Migration Errors

**Error**: `django.db.migrations.exceptions.InconsistentMigrationHistory`

**Solution**: Check migration state:
```bash
docker compose exec netbox python manage.py showmigrations netbox_netbox_auto_discovery_plugin
```

If migrations are missing:
```bash
# Make sure DEVELOPER=true is set
docker compose exec netbox python manage.py makemigrations netbox_netbox_auto_discovery_plugin
docker compose exec netbox python manage.py migrate netbox_netbox_auto_discovery_plugin
```

### Permission Denied

**Error**: `PermissionError: [Errno 13] Permission denied`

**Solution**: Fix volume mount permissions:
```bash
chmod -R 755 /home/hamidzmz/NetboxPr/netbox-netbox-auto-discovery-plugin
```

### Menu Not Appearing

**Solution**:
1. Verify plugin is in `PLUGINS` list in `configuration/plugins.py`
2. Restart all services:
   ```bash
   docker compose restart
   ```
3. Clear browser cache
4. Check browser console for JavaScript errors

---

## Verifying Installation

### Check Plugin Status

```bash
# List installed plugins
docker compose exec netbox python manage.py nbshell

# In the shell:
from netbox.plugins import get_plugins
for plugin in get_plugins():
    print(f"{plugin.name}: {plugin.version}")
```

### Check Database Tables

```bash
# Enter PostgreSQL
docker compose exec postgres psql -U netbox

# List plugin tables
\dt netbox_netbox_auto_discovery_plugin_*

# Expected output:
# netbox_netbox_auto_discovery_plugin_scanner
# netbox_netbox_auto_discovery_plugin_scanrun
# netbox_netbox_auto_discovery_plugin_discovereddevice
# netbox_netbox_auto_discovery_plugin_discoveredipaddress
```

### Test Plugin Functionality

1. Navigate to **Plugins > Auto Discovery > Scanners**
2. Click **Add Scanner**
3. Fill in the form:
   - Name: "Test Scanner"
   - Scanner Type: Network Range Scan
   - CIDR Range: 192.168.1.0/24
4. Click **Create**
5. Verify the scanner appears in the list

---

## Updating the Plugin

### For Development (Method 1)

Simply edit the plugin files in `/home/hamidzmz/NetboxPr/netbox-netbox-auto-discovery-plugin/`.

If you change models:
```bash
docker compose exec netbox python manage.py makemigrations netbox_netbox_auto_discovery_plugin
docker compose exec netbox python manage.py migrate
docker compose restart netbox netbox-worker
```

### For Production (Method 2)

Update `plugin_requirements.txt` with the new version/branch:
```bash
git+https://github.com/hamidzmz/netbox-netbox-auto-discovery-plugin.git@v0.2.0
```

Then rebuild:
```bash
docker compose down
docker compose build --no-cache netbox
docker compose up -d
docker compose exec netbox python manage.py migrate netbox_netbox_auto_discovery_plugin
```

---

## Uninstalling the Plugin

### Step 1: Remove from Configuration

Edit `configuration/plugins.py` and remove the plugin from `PLUGINS` list.

### Step 2: Unapply Migrations

```bash
docker compose exec netbox python manage.py migrate netbox_netbox_auto_discovery_plugin zero
```

### Step 3: Remove from Requirements

Delete or comment out the plugin line in `plugin_requirements.txt`.

### Step 4: Rebuild

```bash
docker compose down
docker compose build --no-cache netbox
docker compose up -d
```

---

## Next Steps

After successful installation:

1. **Create your first scanner** (see README.md)
2. **Implement Phase 2** (background jobs for actual scanning)
3. **Test with virtual switches** (GNS3/Containerlab)
4. **Configure scan schedules**
5. **Set up notifications** (future feature)

For more information, see:
- [Plugin README](../README.md)
- [Migration Guide](migrations.md)
- [Phase 1 Summary](phase1-summary.md)
