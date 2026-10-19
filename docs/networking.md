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

Before enabling a full-tunnel route, preserve a route to the UDP endpoint.
Before changing firewall rules, capture the existing rules and provide a
rollback path. A Kill Switch is not implemented by the Rust library yet.

Configuration validation does not apply routes, firewall rules, DNS settings,
or NAT rules. Those operations remain in a privileged platform/deployment
layer and must preserve an endpoint exception route plus a rollback path.

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
