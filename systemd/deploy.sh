#!/usr/bin/env bash
# Copies this repo's hids.service / hids-dashboard.service into /etc/systemd/system,
# reloads systemd, and restarts both units. Run manually whenever the unit files change
# (e.g. after the 2026-10-20 stale-bun-path fix).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

sudo cp "$SCRIPT_DIR/hids.service" /etc/systemd/system/hids.service
sudo cp "$SCRIPT_DIR/hids-dashboard.service" /etc/systemd/system/hids-dashboard.service
sudo systemctl daemon-reload
sudo systemctl restart hids.service hids-dashboard.service

sleep 2
systemctl status hids.service hids-dashboard.service --no-pager
