# 03 — Multicast egress pinning (`IP_MULTICAST_IF`)

## Goal

Pin WS-Discovery multicast *egress* to the configured `server_ip` NIC on Windows, so the one-shot `Hello`/`Bye` announcements leave on the camera/NVR subnet rather than the OS default-route NIC. Today `bind_multicast_socket` (`onvif_discovery.rs:424`) joins the group on the right interface but cannot set egress — `std` does not expose `IP_MULTICAST_IF` — so on a multi-homed host a `Hello`-only NVR on the camera subnet may never see the device announce.

## Context

`bind_multicast_socket` already receives `iface: Option<Ipv4Addr>` (the advertised `server_ip`) and uses it for the `join_multicast_v4` membership. The Probe→ProbeMatch flow (unicast reply to the probe sender) already routes correctly; only the unsolicited `Hello`/`Bye` multicast sends (`send_announce`) are affected, because they egress via the kernel's route for `239.255.255.250` which may be the wrong NIC. The module already has a `windows_ffi` submodule (`onvif_discovery.rs:439`) with `#[link(name="ws2_32")]` and `setsockopt`/`socket`/`bind` declarations — the FFI scaffolding for adding `IP_MULTICAST_IF` is already present.

## Scope

In: a Windows-only `setsockopt(IP_MULTICAST_IF)` call in `bind_multicast_socket` when `iface` is `Some`, reusing the existing `windows_ffi` FFI; a Linux path (the test host) that is a no-op (std has no `IP_MULTICAST_IF` setter, and the test suite does not exercise multi-homed egress); a log line confirming egress was pinned.

Out: changing the bind address (stays `0.0.0.0:3702`); changing `SO_REUSEADDR` handling; touching the `Hello`/`Bye`/`ProbeMatch` XML builders; any change to `send_announce`'s timeout logic.

## Approach

1. In `onvif_discovery::windows_ffi`, add the `IPPROTO_IP` constant (`0`) and the `IP_MULTICAST_IF` option number (`0x9` / `9`), and reuse the existing `setsockopt` extern declaration (it is already declared with the right signature). No new extern fn needed.
2. In `bind_multicast_socket`, after the successful `join_multicast_v4` and only `#[cfg(windows)]`, when `iface` is `Some(ip)`: build a `u32` in network byte order from `ip.octets()` (the `in_addr` form `setsockopt` expects for `IP_MULTICAST_IF`), and call `setsockopt` at level `IPPROTO_IP`, option `IP_MULTICAST_IF`, with that 4-byte value. Convert a `SOCKET_ERROR` (-1) return into an `io::Error` via `WSAGetLastError` and return it (egress pinning is a correctness fix, not best-effort — failing to pin should be visible). On non-Windows, the block is absent.
3. To call `setsockopt` on the std `UdpSocket`, use `std::os::windows::io::AsRawSocket` to get the raw handle (the `windows_ffi` module already imports `FromRawSocket`; add `AsRawSocket` for the read direction). Pass it to the same `setsockopt` extern.
4. Update the `NOTE` comment at `onvif_discovery.rs:432` that says multicast egress is not pinned: replace it with a note that egress is now pinned to `iface` on Windows via `IP_MULTICAST_IF`, and remains OS-default on non-Windows (where multi-homed hosts are not a supported deployment and the test host has one NIC).
5. The `DiscoveryWithLogger::run` startup log already prints the joined interface (`via {ip}`); optionally extend it to confirm egress is pinned. Keep it one log line.

## Test

FFI/socket-option code cannot be exercised on the Linux host. Verify mechanically:
- `cargo build --target x86_64-pc-windows-gnu` compiles the new `setsockopt` call and constants.
- Add a Linux-visible unit test that `bind_multicast_socket(None)` still succeeds (the `None` path must not attempt the Windows-only pin) — this guards the cfg gating. The `Some(iface)` Windows path is covered by the cross-compile plus a manual Windows smoke test noted in acceptance.

## Files

- `src/onvif_discovery.rs` — `windows_ffi` constants, `bind_multicast_socket` egress pin, `NOTE` comment, optional log extension, Linux guard test.

## Acceptance

- On Windows with a configured `server_ip`, `Hello`/`Bye` egress on the correct NIC (verified by a manual smoke test on a multi-homed Windows host, or by code review if no such host is available — note which).
- `bind_multicast_socket(None)` still succeeds on Linux; the Windows path cross-compiles clean.
- Host build, clippy `-D warnings`, `cargo test`, and `cargo build --target x86_64-pc-windows-gnu` green.

## Notes

- `IP_MULTICAST_IF` takes the interface's IPv4 address (not an interface index) — same value already used for `join_multicast_v4`, so no new resolution is needed.
- Do not add `IP_MULTICAST_TTL` work here; the default TTL (1) is correct for link-local WS-Discovery. If a future routed-multicast need appears, that is separate work.
