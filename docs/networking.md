# Linux networking notes

The current Rust core provides a Linux TUN adapter and UDP transport. Network
namespace integration, IP forwarding, nftables MASQUERADE, route management,
DNS setup/restoration, IPv6 addressing, and endpoint exception routes are
deployment work rather than automatic side effects of the library.

The intended initial values are:

- VPN IPv4 range: `10.80.0.0/16`
- server address: `10.80.0.1`
- UDP port: `51820`
- tunnel MTU: `1400`
- IPv6 range: `fd80:1234:5678::/64`

The Rust core exposes these values through `TunnelNetworkConfig`. Its default
policy is dual-stack and uses UDP port `51820`. The encrypted payload budget
is derived from the configured MTU: `1400 - 24-byte header - 16-byte AEAD tag
= 1360 bytes`. Invalid server addresses, zero ports, and MTUs below the
IPv6-safe minimum are rejected before an engine starts.

`MtuBudget::validate_inner_packet` validates a complete IPv4 or IPv6 packet
against that encrypted payload budget. It identifies the address family,
checks exact header and total lengths, verifies the IPv4 header checksum, and
rejects IPv6 when dual-stack mode is disabled. Packet fragmentation and
reassembly are outside the initial scope; callers should reject packets above
the derived budget before encryption.

Before enabling a full-tunnel route, preserve a route to the UDP endpoint.
Before changing firewall rules, capture the existing rules and provide a
rollback path. The Rust library only builds a declarative Kill Switch plan;
the privileged adapter still owns rule application and rollback.

Configuration validation does not apply routes, firewall rules, DNS settings,
or NAT rules. Those operations remain in a privileged platform/deployment
layer and must preserve an endpoint exception route plus a rollback path.

`DnsPolicy` validates an ordered list of IPv4/IPv6 upstreams and search
domains. It can represent UDP, TCP, DoT, and DoH transports for a future
resolver implementation, while `LinuxDnsPlan` currently emits only the
`resolvectl` form supported by the host adapter: port 53 over UDP or TCP.
The ordered list is retained so a resolver adapter can implement upstream
fallback without changing the control-plane model.

Before applying a tunnel policy, capture the current resolver addresses and
domains in `DnsSnapshot`. `LinuxDnsPlan::restore_commands` first reverts the
link and then restores the captured values, followed by a cache flush. The
Rust library only returns argv-safe command records; it never changes the
host resolver itself.

`LinuxNetworkPlan` is the boundary between the validated policy and that
privileged layer. It emits argv-safe `ip`, `sysctl`, and `nft` command records
for server interface setup, IPv4 MASQUERADE, optional IPv6 addressing, and
cleanup. It never executes commands. Interface names are restricted to safe
Linux device-name characters, and an endpoint inside the VPN address space is
rejected to prevent a routing loop.

`LinuxClientRoutePlan` emits the client-side route transition in a safe order:
first an endpoint host route through the physical gateway, then the IPv4
default route (and the IPv6 default route for dual-stack policy) through the
TUN interface. Its cleanup plan removes only the routes it introduced. The
privileged caller still owns route snapshots, restoration of pre-existing
routes, and recovery after an interrupted process.

`LinuxClientNetworkPlan` adds validated IPv4/IPv6 addresses for the TUN
interface and emits address setup before routing, followed by reverse cleanup.
It is still a command planner; applying the commands and restoring a route
snapshot belong to the privileged platform adapter.

`LinuxRouteSnapshot` captures the pre-VPN IPv4/IPv6 default routes and the
physical Endpoint route. `LinuxClientRoutePlan::cleanup_commands_with_snapshot`
removes the VPN routes first, then restores only the validated snapshot entries.
The snapshot is rejected when its gateway family does not match its route or
when an IPv6 route is supplied to an IPv4-only plan. This makes restoration
replayable after an interrupted cleanup without allowing arbitrary command
arguments into the planner.

`TunnelNetworkConfig::kill_switch_plan` returns no plan unless `kill_switch`
is explicitly enabled. `LinuxKillSwitchPlan` then emits an optional nftables output chain with a default
drop policy. Loopback, tunnel-interface traffic, established/related
traffic, and the VPN UDP Endpoint through the physical interface are allowed.
Rollback deletes the dedicated nftables table. The plan does not execute
firewall changes; the privileged adapter must apply it atomically and retain
the rollback command for abnormal termination recovery.

`ClientAddressPool` allocates paired client addresses starting at
`10.80.0.2` and `fd80:1234:5678::2`, skips the server and network/broadcast
addresses, and releases both families as one unit. Capacity exhaustion is
reported before a partial pair can escape to the caller.

The management configuration reserves payload byte 8 for the explicit NAT66
policy. When enabled with dual-stack mode, `LinuxNetworkPlan` emits an IPv6
MASQUERADE rule; the default remains disabled so routed IPv6 can be selected
without silently applying NAT.
