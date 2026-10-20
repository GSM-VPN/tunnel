#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "Linux TUN smoke test requires Linux" >&2
  exit 77
fi

if [[ "$(id -u)" -ne 0 ]]; then
  echo "run this test as root so it can create a network namespace and TUN device" >&2
  exit 1
fi

command -v ip >/dev/null
command -v ping >/dev/null

helper_binary="${LINUX_TUN_BINARY:-target/debug/examples/linux-tun-smoke}"
if [[ -z "${LINUX_TUN_BINARY:-}" ]]; then
  cargo build -p tunnel-core --example linux-tun-smoke
fi

if [[ "${GSM_TUN_NAMESPACE:-0}" != "1" ]]; then
  exec env GSM_TUN_NAMESPACE=1 unshare --net --mount-proc "$0" "$@"
fi

ip link set lo up

work_dir=$(mktemp -d)
output_file="$work_dir/helper.log"
start_file="$work_dir/start"
helper_pid=''

cleanup() {
  if [[ -n "$helper_pid" ]] && kill -0 "$helper_pid" 2>/dev/null; then
    kill "$helper_pid" 2>/dev/null || true
    wait "$helper_pid" 2>/dev/null || true
  fi
  ip link delete gsmtest0 2>/dev/null || true
  rm -rf "$work_dir"
}
trap cleanup EXIT

GSM_TUN_START_FILE="$start_file" "$helper_binary" >"$output_file" 2>&1 &
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

grep -q '^ready name=gsmtest0 mtu=1500$' "$output_file"
cat "$output_file"
ip link show
ip link set gsmtest0 up
ip addr add 10.80.0.1/16 dev gsmtest0
ip route add 10.80.0.2/32 dev gsmtest0
touch "$start_file"

ping -c 1 -W 1 -I gsmtest0 10.80.0.2 >/dev/null 2>&1 &
ping_pid=$!
wait "$helper_pid"
helper_pid=''
kill "$ping_pid" 2>/dev/null || true
wait "$ping_pid" 2>/dev/null || true

grep -q '^read bytes=' "$output_file"
grep -q '^written bytes=' "$output_file"
grep -q '^closed$' "$output_file"
if ip link show gsmtest0 >/dev/null 2>&1; then
  echo "TUN interface survived helper shutdown" >&2
  exit 1
fi

cat "$output_file"
