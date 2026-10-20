#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "Linux TUN pair test requires Linux" >&2
  exit 77
fi

if [[ "$(id -u)" -ne 0 ]]; then
  echo "run this test as root so it can create a network namespace and TUN devices" >&2
  exit 1
fi

command -v ip >/dev/null
command -v ping >/dev/null
helper_binary="${LINUX_TUN_PAIR_BINARY:-target/debug/examples/linux-tun-pair}"

if [[ -z "${LINUX_TUN_PAIR_BINARY:-}" ]]; then
  cargo build -p tunnel-core --example linux-tun-pair
fi

if [[ "${GSM_TUN_NAMESPACE:-0}" != "1" ]]; then
  exec env GSM_TUN_NAMESPACE=1 unshare --net --mount-proc "$0" "$@"
fi

ip link set lo up
work_dir=$(mktemp -d)
output_file="$work_dir/helper.log"
stop_file="$work_dir/stop"
helper_pid=''

cleanup() {
  if [[ -n "$helper_pid" ]] && kill -0 "$helper_pid" 2>/dev/null; then
    kill "$helper_pid" 2>/dev/null || true
    wait "$helper_pid" 2>/dev/null || true
  fi
  ip link delete gsmclient0 2>/dev/null || true
  ip link delete gsmserver0 2>/dev/null || true
  rm -rf "$work_dir"
}
trap cleanup EXIT

GSM_TUN_STOP_FILE="$stop_file" "$helper_binary" >"$output_file" 2>&1 &
helper_pid=$!

for _ in $(seq 1 50); do
  if grep -q '^ready ' "$output_file"; then
    break
  fi
  if ! kill -0 "$helper_pid" 2>/dev/null; then
    cat "$output_file" >&2
    exit 1
  fi
  sleep 0.1
done

grep -q '^ready client=gsmclient0 server=gsmserver0$' "$output_file"
ip link set gsmclient0 up
ip link set gsmserver0 up
ip addr add 10.82.0.1 peer 10.82.0.2 dev gsmclient0
ip addr add 10.82.0.2 peer 10.82.0.1 dev gsmserver0

if ! ping -c 2 -W 1 -I gsmclient0 10.82.0.2; then
  cat "$output_file" >&2
  exit 1
fi

touch "$stop_file"
wait "$helper_pid"
helper_pid=''
grep -q '^closed$' "$output_file"
if ip link show gsmclient0 >/dev/null 2>&1 || ip link show gsmserver0 >/dev/null 2>&1; then
  echo "TUN interfaces survived helper shutdown" >&2
  exit 1
fi

cat "$output_file"
