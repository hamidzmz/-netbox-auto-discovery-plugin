# NetBox Auto Discovery Plugin - Quick Reference

## For Interviewers/Evaluators

### Initial Setup (First Time Only)

```bash
# 1. Clone the repository
git clone <repository-url>
cd <repository-name>

# 2. Optional: Run pre-flight check
chmod +x preflight-check.sh
./preflight-check.sh

# 3. Run automated setup
chmod +x setup-monorepo.sh
./setup-monorepo.sh

# Wait 5-10 minutes for setup to complete
```

### Access NetBox

- **URL:** http://localhost:8000
- **Username:** admin
- **Password:** admin

### Quick Test Path

1. Login to NetBox
2. Navigate: **Plugins** → **Auto Discovery** → **Scanners**
3. Click **"Add Scanner"**
4. Create a Network Range Scanner:
   - Name: `Test Scan`
   - Type: `Network Range Scan`
   - IP Range: `192.168.1.0/24`
   - Status: `Active`
5. Click **"Create"**
6. Click **"Run Scan"** button
7. Wait 1-5 minutes
8. Refresh page to see results
9. View: **IPAM** → **IP Addresses** (discovered IPs appear here)

### Essential Commands

```bash
# View logs
cd netbox-docker && docker compose logs -f netbox

# Stop everything
cd netbox-docker && docker compose down

# Start everything
cd netbox-docker && docker compose up -d

# Restart services
cd netbox-docker && docker compose restart

# Check status
cd netbox-docker && docker compose ps

# Enter container
cd netbox-docker && docker compose exec netbox bash
```

### API Testing

```bash
# 1. Get API token from UI:
#    Login → Click username → API Tokens → Add a token

# 2. Test API
curl -H "Authorization: Token YOUR_TOKEN" \
     http://localhost:8000/api/plugins/auto-discovery/scanners/

# 3. Create scanner via API
curl -X POST \
     -H "Authorization: Token YOUR_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"name":"API Scanner","scanner_type":"network_range","status":"active","ip_range":"10.0.0.0/24"}' \
     http://localhost:8000/api/plugins/auto-discovery/scanners/
```

### Troubleshooting

| Problem | Solution |
|---------|----------|
| Port 8000 in use | `sudo lsof -i :8000` and kill process |
| Services won't start | `docker compose logs` to check errors |
| Plugin not visible | `docker compose restart netbox` |
| Migration errors | `docker compose down -v` then re-run setup |

### Documentation

- **Main README:** `./README.md`
- **Plugin README:** `./netbox-netbox-auto-discovery-plugin/README.md`
- **Architecture:** `./netbox-netbox-auto-discovery-plugin/ARCHITECTURE.md`
- **Deployment:** `./netbox-netbox-auto-discovery-plugin/DEPLOYMENT_GUIDE.md`
- **API Docs:** http://localhost:8000/api/docs/

### What to Evaluate

- ✅ Code quality and structure
- ✅ UI/UX design and usability
- ✅ Functionality (network/Cisco scans)
- ✅ REST API completeness
- ✅ Data model design
- ✅ Error handling
- ✅ Documentation quality

### System Requirements

- Docker 20.10+
- Docker Compose 2.0+
- 4GB RAM minimum
- 10GB disk space
- Linux/macOS/Windows with WSL2

### Contact

**Author:** Hamid Zamani
**Email:** hamidzamani445@gmail.com
**Purpose:** Technical Interview/Evaluation

---

**Thank you for testing this project!** 🚀
