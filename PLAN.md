# UTUN IPv6 Implementation Plan (Revised: SLAAC Support)

This plan outlines the implementation of IPv6 support in `utun` using ICMPv6 Router Advertisements (RA) to enable SLAAC for clients and their subnets.

## 1. Goal
- Support IPv6 traffic within the VPN.
- Implement a **SLAAC-based** auto-configuration mechanism (simulating `radvd`).
- Support devices behind clients (e.g., t3) to automatically obtain IPv6 addresses from the shared `/64` prefix.
- Dynamic routing on the server based on observed client IPv6 traffic.

## 2. Architecture Changes

### A. Server as an IPv6 Router (`pkg/router`)
- **RA Generator**: The server will periodically generate and send ICMPv6 Router Advertisement (Type 134) packets into the tunnel.
- **Prefix Information**: The RA will contain the configured `/64` prefix with the "Autonomous" (A) flag set, allowing clients to perform SLAAC.
- **Multicast Handling**: Since `utun` is L3, the server will "broadcast" RA packets by replicating them to all active sessions (or sending to the all-nodes multicast `ff02::1`).

### B. Dynamic Routing & Learning (`pkg/router`)
- **Source IP Learning**: Since addresses are autoconfigured by clients, the server cannot pre-assign them in a config file.
- **Learning Logic**: When the server receives an IPv6 packet from a session, it will:
    1. Extract the source IPv6 address.
    2. Dynamically add/update a `/128` route for that IP pointing to the respective session.
    3. (Optional) Implement a short timeout for these learned routes.

### C. ICMPv6 Handling (`pkg/transport` / `pkg/router`)
- **Router Solicitation (RS)**: The server should listen for RS (Type 133) packets from clients and immediately respond with a Uni-cast or Multi-cast RA.
- **Neighbor Discovery (NDP)**: Although `utun` is L3, some OS stacks might still try to perform Neighbor Solicitation. The `Engine` should be prepared to handle or respond to these if necessary (Proxy NDP emulation).

### D. TUN Device & OS Integration (`pkg/tun`)
- **IPv6 Forwarding**: The server must ensure IPv6 forwarding is enabled on its `utun` interface.
- **Accept RA**: Clients must be configured to accept RAs on the `utun` interface (`accept_ra=2` in Linux to accept RAs even if forwarding is enabled).

## 3. Implementation Steps

1.  **Refactor Config**: Add `ip6_prefix` (e.g., `2001:db8::/64`) to `server.cfg`.
2.  **RA Packet Construction**: Implement logic to build valid ICMPv6 RA packets (including Prefix Information Option).
3.  **Engine Update**:
    - Add a background goroutine on the server to send periodic RAs.
    - Update `handleInbound` to detect IPv6 and perform "Source IP Learning" for routing.
4.  **IPv6 Header Parsing**: Enhance `pkg/router/engine.go` to correctly extract IPv6 source/destination addresses.
5.  **Client-side Integration**:
    - Ensure the `utun` interface is brought up with IPv6 enabled.
    - Verify that the OS automatically generates an address upon receiving the RA.
6.  **Proxy NDP for Subnets**: Client (t2) may need to relay RAs to its local interface (`eth1`) or perform Proxy NDP for `t3`.

## 4. Verification Plan
- **SLAAC Test**:
    1. Start server with `2001:db8:1::/64`.
    2. Start client `t2`.
    3. Verify `t2`'s `utun1` interface automatically gets an address like `2001:db8:1:[EUI-64]`.
    4. Verify `t3` (behind `t2`) also gets an address from the same prefix (if relayed).
- **Connectivity**: `ping6` from `t3` to server's IPv6.
