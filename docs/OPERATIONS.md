# Operations Guide

Day-2 operations for running LLM Portal in production.

## Monitoring

### Check service status

```bash
systemctl status llm-portal llm-proxy rotate-logs.timer
```

### View logs

```bash
# Portal application logs (journal)
journalctl -u llm-portal -f

# Proxy logs (journal)
journalctl -u llm-proxy -f

# Request access logs
tail -f logs/access/access.log

# Error logs
tail -f logs/error/error.log

# Authentication audit
tail -f logs/auth/auth.log

# System events
tail -f logs/events/events.log
```

### Health check

```bash
# Portal is up
curl -sf http://127.0.0.1:8081/portal/login > /dev/null && echo "portal OK"

# Proxy is up
curl -sf http://127.0.0.1:8080/health > /dev/null && echo "proxy OK"

# Backend is up (via proxy)
curl -sf -H "Authorization: Bearer YOUR_KEY" http://127.0.0.1:8080/v1/models > /dev/null && echo "backend OK"
```

### Useful queries

```bash
# Requests in the last hour
grep "$(date +%Y-%m-%dT%H)" logs/access/access.log | wc -l

# Failed auth attempts today
grep "401" logs/access/access.log | grep "$(date +%Y-%m-%d)" | wc -l

# Top 10 users by request count (last 24h)
grep -oP 'user=\S+' logs/access/access.log | sort | uniq -c | sort -rn | head -10

# Errors in the last hour
grep "$(date +%Y-%m-%dT%H)" logs/error/error.log | tail -20
```

## Backup

### What to back up

| File | Frequency | Why |
|------|-----------|-----|
| `config.toml` | On change | Server configuration |
| `data/portal.db` | Daily | User accounts, sessions, audit |
| `data/api_keys.txt` | Daily | API keys (source of truth) |

### Backup script

```bash
#!/usr/bin/env bash
set -euo pipefail
BACKUP_DIR="/backups/llm-portal"
DATE="$(date +%F)"
mkdir -p "$BACKUP_DIR"

cp config.toml "$BACKUP_DIR/config-$DATE.toml"
cp data/portal.db "$BACKUP_DIR/portal-$DATE.db"
cp data/api_keys.txt "$BACKUP_DIR/api_keys-$DATE.txt"

# Retain 30 days
find "$BACKUP_DIR" -mtime +30 -delete

echo "Backed up to $BACKUP_DIR on $DATE"
```

### Restore

```bash
# Stop services
systemctl stop llm-portal llm-proxy

# Restore files
cp /backups/llm-portal/config-2026-10-19.toml config.toml
cp /backups/llm-portal/portal-2026-10-19.db data/portal.db
cp /backups/llm-portal/api_keys-2026-10-19.txt data/api_keys.txt

# Fix permissions
chmod 600 data/portal.db data/api_keys.txt

# Restart
systemctl start llm-portal llm-proxy
```

## Upgrades

```bash
# Stop services
sudo systemctl stop llm-portal llm-proxy

# Back up first!
./backup.sh

# Pull latest code
cd /opt/llm-portal
git pull origin main

# Check for config changes
diff config.toml config.example.toml

# Restart
sudo systemctl start llm-portal llm-proxy

# Verify
curl -sf http://127.0.0.1:8081/portal/login > /dev/null && echo "OK"
```

## Common tasks

### Rotate a user's API key

```bash
# Via CLI
./userctl.sh revoke alice

# Via portal: Admin tab → find user → Rotate
```

### Disable a user

```bash
./userctl.sh disable alice
# Or via portal: Admin tab → find user → Disable
```

### Reset a user's portal password

```bash
# Via portal: Admin tab → find user → Reset PW
# (CLI password reset requires portal access)
```

### Create a new superadmin

```bash
# Via portal: Admin tab → Create user → Role: superadmin
# Or via CLI bootstrap (if no superadmin exists):
PORTAL_BOOTSTRAP_PASSWORD=changeme python3 -m llm_portal.app createsuperuser admin
```

### Add a user without the portal

```bash
./userctl.sh add bob
./userctl.sh show bob    # print the key
```

### Clear rate limiting (locked out)

The rate limiter resets automatically after 10 minutes. To clear immediately:

```bash
systemctl restart llm-portal
```

### Rotate logs manually

```bash
./scripts/rotate-logs.sh
```

### Migrate to a new server

```bash
# On old server
tar czf llm-portal-backup.tar.gz config.toml data/

# On new server
tar xzf llm-portal-backup.tar.gz
sudo systemctl enable --now llm-portal llm-proxy
```

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Portal won't start | Port already in use | `ss -tlnp \| grep 8081` and kill/reconfigure |
| Portal starts but 500 errors | DB corruption | Restore from backup, or delete `data/portal.db` to reinit |
| API returns 401 | Key mismatch or user disabled | `./userctl.sh list` to check status |
| API returns 404 | Backend not running | Check `backend.url` in config, start inference server |
| Proxy returns 502 | Backend not responding | Check backend health, restart it |
| All requests show "anon" | Key file not readable | Check permissions: `chmod 600 data/api_keys.txt` |
| Styling broken | Accessing portal directly (no proxy) | Access via proxy port 8080, not 8081 |
| Slow responses | Model overloaded | Reduce concurrent slots in backend config |
| Login always fails | Wrong password | Check `logs/auth/auth.log` for failure reason |
| Sessions expire too fast | Config value | Increase `portal.session_hours` in config.toml |

## Log rotation

Logs rotate daily at 00:05 and are retained for 7 days (configurable).

```bash
# Check rotation status
systemctl status rotate-logs.timer

# View rotation history
grep rotate_logs logs/events/events.log

# Change retention
# Edit config.toml: logging.retention_days = 14
# Then update scripts/rotate-logs.sh find command
```

## Performance tuning

### Portal is slow

- The portal handles thousands of concurrent users with stdlib threading
- SQLite is sufficient for most deployments
- Check disk I/O: `iostat -x 1`

### Proxy is slow

- The proxy uses asyncio — single process handles 10k+ connections
- Check for slow backend: `grep -E '[0-9]{4,}ms' logs/access/access.log`
- Enable `proxy_buffering off` in your TLS reverse proxy for streaming

### Log disk usage

```bash
# Check log sizes
du -sh logs/*/

# If logs are too large, reduce retention
# Edit scripts/rotate-logs.sh: find ... -mtime +3
```
