#!/usr/bin/env bash
set -euo pipefail

OBJ="${1:-internal/ebpf/kernelpulse_bpfel.o}"
PIN_BASE="${2:-/sys/fs/bpf/kernelpulse_selftest}"
LOG="${3:-/tmp/kernelpulse-verifier.log}"

if [[ ! -f "$OBJ" ]]; then
  echo "missing object: $OBJ"
  exit 1
fi

if ! command -v bpftool >/dev/null 2>&1; then
  echo "[kernelpulse] skipping bpftool selftest: bpftool is not available on this runner"
  exit 0
fi

cleanup() {
  sudo rm -rf "$PIN_BASE" >/dev/null 2>&1 || true
}
trap cleanup EXIT

mkdir -p "$(dirname "$LOG")"
rm -f "$LOG"

echo "[kernelpulse] loading $OBJ with verifier logs"
if ! sudo bpftool prog loadall "$OBJ" "$PIN_BASE" 2>"$LOG"; then
  echo "[kernelpulse] verifier rejected program"
  grep -E "invalid|stack|loop|R[0-9]|permission|context" "$LOG" || true
  echo "---- full verifier log ----"
  cat "$LOG"
  exit 1
fi

echo "[kernelpulse] BPF load selftest passed"
