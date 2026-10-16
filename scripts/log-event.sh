#!/usr/bin/env bash
# log_event.sh — append one event line to logs/events/events.log
#   usage: ./log_event.sh "any message"  |  log from scripts / systemd
set -euo pipefail
LOG_DIR="${LOG_DIR:-${LOG_DIR:-./logs}}"
mkdir -p "$LOG_DIR/events"
printf '%s\t%s\n' "$(date '+%Y-%m-%dT%H:%M:%S%z')" "${1:-}" >> "$LOG_DIR/events/events.log"
