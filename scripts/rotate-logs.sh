#!/usr/bin/env bash
# rotate_logs.sh — daily log rotation with 7-day retention.
# Moves each current log to a dated archive and prunes anything older than 7 days.
# Run by the `rotate-logs.timer` systemd unit (daily), or manually whenever:
#   ./rotate_logs.sh
set -euo pipefail

LOG_ROOT="${LOG_ROOT:-${LOG_ROOT:-./logs}}"
TODAY="$(date +%F)"

rotated=0
for kind in access error events server auth; do
  cur="$LOG_ROOT/$kind/$kind.log"
  [[ -f "$cur" ]] || continue
  size="$(stat -c %s "$cur" 2>/dev/null || echo 0)"
  if (( size > 0 )); then
    mv "$cur" "$LOG_ROOT/$kind/$kind-$TODAY.log"
    rotated=$((rotated + 1))
  fi
done

# retention: delete every log older than 7 days (all .log + dated archives)
pruned_count="$(find "$LOG_ROOT" -type f -name '*.log' -mtime +7 | wc -l)"
find "$LOG_ROOT" -type f -name '*.log' -mtime +7 -delete

echo "$(date -Iseconds) rotate_logs: rotated=$rotated pruned=$pruned_count kept_after_7d=no"
