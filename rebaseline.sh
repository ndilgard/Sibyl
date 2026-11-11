#!/usr/bin/env bash
# Rebuilds the fim/process/network baselines. Run this after Sibyl has been down for a
# while and comes back up to a flood of "trusted binary changed since last verified"
# false positives from normal system updates during the downtime (seen 2026-10-20 after
# a 23-day outage caused by the hids.service bun-path bug).
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

bun run src/cli.ts init fim "$@"
bun run src/cli.ts init process "$@"
bun run src/cli.ts init network "$@"
