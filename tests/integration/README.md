# Lifeline Integration Tests (Linux Network Namespaces)

`run_netns_tests.py` exercises the real kernel networking stack, `dnsmasq`,
`nftables`, `ip rule` / `table 200`, `AF_PACKET` raw `DHCPDISCOVER` / `ARP`
probes, and IPv6 link-local `BeaconBus` multicast inside an isolated Linux user +
network namespace (`unshare -Urn`), without modifying the host network.

## Running

```bash
cd /usr/local/google/home/viki/xkdr/linux/lifeline
# Unprivileged mode (uses unshare -Urn; validates dnsmasq config and runs
# a lightweight static DHCP responder + full kernel nftables/rp_filter/multicast):
python3 tests/integration/run_netns_tests.py

# Full root mode (uses unshare -n and spawns the real dnsmasq binary too):
sudo python3 tests/integration/run_netns_tests.py
```

## What It Verifies

1. **Raw `DHCPDISCOVER` & `ARP` probes over a real Linux bridge/veth**:
   - Launches real `dnsmasq` in `PRIMARY` table-only mode.
   - Verifies that a client whose MAC is in `dhcp_hosts.csv` receives a `DHCPOFFER` with `192.168.9.101` from `192.168.9.24`.
   - Verifies that an unknown MAC receives **no** `DHCPOFFER`.
   - Verifies that `probe_arp_conflict_sync` detects an `ETH_IP` (`192.168.9.24`) collision on the wire.
2. **Active-Lease `nftables` Forwarding & Anti-Spoof Counters**:
   - Loads real `table inet lifeline` rules via `nft -f -`, exercises `lease_hook.handle_lease_event` to dynamically insert `(ip . mac)` into `allowed_v4` and `mac` into `allowed_v6_mac`, and verifies `nft list table inet lifeline` elements.
   - Loads the `BLOCK` ruleset and confirms forwarding drops are active.
3. **Policy-Routed Wi-Fi Probe Under `rp_filter=1`**:
   - Enables `net.ipv4.conf.all.rp_filter=1`, installs a lower-metric default route on `eth0` (simulating `FAILOVER`), installs `PolicyRouteManager` (`table 200` for `wifi0`), and verifies `probe_wifi_connectivity` succeeds strictly through `wifi0`!
4. **Multi-Laptop Link-Local IPv6 `BeaconBus` Election**:
   - Spins up two `BeaconBus` instances across a `veth` link and verifies peer discovery, `PRIMARY` detection, and deterministic rank ordering.
