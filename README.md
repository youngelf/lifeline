# Lifeline

**Lifeline** is a fail-safe, zero-dependency Python 3 (stdlib-only) daemon for **Ubuntu 26.04 (x64)** laptops equipped with both **Wi-Fi** and **Ethernet**. It allows up to 5 (or more) laptops running the exact same code to share an Ethernet switch/plug alongside client devices and/or an external router:

- **When Wi-Fi is healthy and no other DHCP server owns the wire (`PRIMARY`):**
  1. Configures Ethernet with a hardcoded static IPv4 address (`ETH_IP`, e.g., `192.168.9.24/24`) and an RFC 4193 IPv6 ULA `/64` address (`<ULA>::24/64`), with no default route on Ethernet.
  2. Starts a supervised `dnsmasq` child process (from `dnsmasq-base`) serving DHCPv4, SLAAC/DHCPv6, and local DNS from a static **MAC → IP table** (`dhcp_hosts.csv`), with an optional fallback **`dynamic_pool`** range for unspecified devices.
  3. Enables **IPv4 and IPv6 forwarding + NAT44/NAT66** (`table inet lifeline` in `nftables`) **only for clients currently holding an active DHCP lease**, automatically following active VPN/tunnel uplinks (Tailscale, WireGuard, OpenVPN, VMware tunnels) via `uplink_mode = "auto_tunnel"` while keeping Wi-Fi health probes pinned to Wi-Fi.
- **When Wi-Fi is healthy, but another DHCP server is already active (`SECONDARY`):**
  1. Keeps Ethernet in **standby DHCP mode** (`never-default`, `ignore-auto-dns`, `may-fail`) with **no DHCP server** and **no IP forwarding** while continuing to use Wi-Fi for internet and DNS.
  2. Routinely probes Ethernet (via raw `AF_PACKET` `DHCPDISCOVER` + `lifeline` link-local multicast beacons) to verify the primary server is still alive.
  3. If the primary goes inactive, runs a deterministic rank-ordered **election** among healthy standby laptops so **at most one** promotes to `PRIMARY`.
- **When Wi-Fi fails (`FAILOVER`):**
  1. Deprecates IPv6 Router Advertisements (`Router Lifetime = 0`), stops `dnsmasq`, drops all Ethernet forwarding in `nftables`, and restores forwarding sysctls.
  2. Configures Ethernet as an active DHCP client (metric `100`, accepting upstream gateway & DNS) and suppresses dead Wi-Fi DNS via `resolvectl`.
  3. Continues probing Wi-Fi reachability **strictly through the Wi-Fi interface** (via policy routing table `200` + `SO_BINDTODEVICE`) until Wi-Fi recovers.

---

## Architecture Overview

```text
                    +-------------------------------------------+
                    |               lifelined                   |
                    |  (asyncio loop, StateMachine, sd_notify)  |
                    +-----+-------+---------+----------+--------+
                          |       |         |          |
        Wi-Fi probes      |       |         |          |  Ethernet coordination
   (table 200 + bind)     |       |         |          |  (ff02::1 UDP + raw DHCP)
            v             |       |         |          v
    +---------------+     |       |         |   +---------------+
    |   probe.py    |     |       |         |   |  election.py  |
    +---------------+     |       |         |   +---------------+
                          v       v         v
         +------------------+   +-------+   +------------------+
         | NetworkBackend   |   |dhcp.py|   |   firewall.py    |
         | (NM / networkd)  |   |dnsmasq|   | (nftables + ufw) |
         +------------------+   +---+---+   +---------+--------+
                                    |                 ^
                                    | --dhcp-script   | nft add/destroy element
                                    +--> lease_hook --+
```

### Why Each Technology Was Chosen

| Component | Choice | Why Not the Alternative? |
| :--- | :--- | :--- |
| **Control daemon** | Python 3.12+ stdlib (`asyncio`) under `systemd` | `NetworkManager/dispatcher.d` bash scripts race on events, lack hysteresis timers, cannot cleanly run a state machine, and leak child processes. Python 3 is preinstalled on Ubuntu 26.04 with `tomllib`, `ipaddress`, and `asyncio` built in—zero `pip` dependencies. |
| **Network configuration** | **NetworkManager runtime profiles** (`nmcli connection add save no …`) + optional `systemd-networkd` backend | Ubuntu 26.04 Desktop uses Netplan with `renderer: NetworkManager`, writing persistent profiles to `/etc/netplan/90-NM-*.yaml`. Using `save no` keeps Lifeline's profiles strictly in-memory so `/etc/netplan` stays untouched. We avoid NM's `ipv4.method=shared` (forces dynamic pool instead of strict MAC table) and `ipv6.method=shared` (requires upstream DHCPv6-PD, unavailable on Wi-Fi). |
| **DHCP / RA / LAN DNS** | **`dnsmasq` binary from `dnsmasq-base`** run as a supervised child | The full `dnsmasq` apt package installs a system service that collides with `systemd-resolved` on port 53. `dnsmasq-base` provides `/usr/sbin/dnsmasq` without a conflicting unit. Running inside `lifeline.service`'s `KillMode=control-group` guarantees `dnsmasq` can never survive a daemon crash. |
| **Forwarding & NAT** | Single isolated **`table inet lifeline`** in `nftables` | Atomic swap via `nft -f -`, unified IPv4+IPv6 filtering, O(1) concatenated `ipv4_addr . ether_addr` anti-spoofing sets, built-in TCP MSS clamping (`maxseg size set rt mtu`), and zero interference with Docker or host firewall rules. |
| **IPv6 strategy** | **ULA (`/64`) + NAT66 (`masquerade`)** | Wi-Fi APs rarely delegate prefixes (DHCPv6-PD). ULA + NAT66 works behind any Wi-Fi network (even `/128` DHCPv6 or AP isolation), gives clients stable addresses across Wi-Fi roams, and automatically sets RA Router Lifetime to `0` if Wi-Fi is IPv4-only. |

---

## State Machine & Transitions

```text
               startup safe default
                        |
                        v
   +--------------> FAILOVER <--------------+
   |             (Wi-Fi unhealthy)          |
   |  Wi-Fi recovered                       | Wi-Fi failed
   |  + DHCP seen                           | (fail_threshold * interval)
   |                                        |
   |   Wi-Fi recovered & no DHCP            |
   |   +--------> ELECTION                  |
   |   |            |                       |
   |   |            | wait rank*backoff     |
   |   |            v                       |
   +---+------- SECONDARY <----yield----- PRIMARY
   |            (Standby)    (ext DHCP    (Static ETH_IP,
   |               |         or higher     dnsmasq active,
   |   primary     |         PRIMARY)      forwarding ON)
   |   missed      |                        ^
   +---------------+------------------------+
                    (ELECTION won)

   * Loss of Ethernet carrier from any state immediately enters IDLE (forwarding OFF, dnsmasq OFF).
```

### Multi-Laptop Coordination (Up to 5 Laptops on One Switch)

All laptops share a simple two-layer coordination mechanism on the Ethernet link:
1. **Raw `AF_PACKET` `DHCPDISCOVER` probes** (`probe.py`):
   - Sends an RFC 2131 `DHCPDISCOVER` frame directly on Ethernet without binding UDP port 68 (so it never collides with NetworkManager's DHCP client).
   - Detects any active external hardware DHCP router *or* another `lifeline` laptop whose table lists this laptop.
2. **Link-local IPv6 multicast beacons** (`election.py`):
   - Every active daemon sends a tiny JSON UDP packet to `ff02::1:41924` bound to the Ethernet interface once per second.
   - Works **even when Ethernet has no IPv4 address** (e.g., a standby laptop omitted from `dhcp_hosts.csv`).
   - Every peer calculates its deterministic rank using `(election.priority, latency_bucket(wifi_rtt_ms), eth_mac)` (lower wins):
    - Among equal-priority laptops, the one with noticeably lower Wi-Fi TCP probe RTT (`latency_bucket_ms = 20.0` avoids jitter flapping) gets Rank `0` and wins promotion.
     - Rank `0` waits `0.5s` before promoting; Rank `N` waits `0.5s + N * rank_backoff_sec`.
     - If two laptops ever enter `PRIMARY` simultaneously (e.g., plugging two switches together), the higher `(priority, mac)` immediately yields to `SECONDARY`.
   - Before claiming `PRIMARY`, the winner performs a final `DHCPDISCOVER` check and an RFC 5227 raw **ARP Duplicate Address Check** for `eth_ip`.

---

## Solving the `FAILOVER` Wi-Fi Recovery Trap

When `lifelined` is in `FAILOVER` mode, Ethernet holds the active default route (metric `100`), while Wi-Fi has metric `600` (or no default route preference). Two kernel mechanisms would break a naive `ping`:
1. **Route shadowing**: Normal sockets exit over Ethernet and falsely conclude "internet is reachable!"
2. **Strict Reverse-Path Filtering (`rp_filter=1`)**: Even with `SO_BINDTODEVICE=wlan0`, reply packets arriving on Wi-Fi are dropped by the kernel if the `main` routing table points to Ethernet.

**How Lifeline solves this (`PolicyRouteManager` in `probe.py`):**
- Whenever Wi-Fi has an IP and gateway, Lifeline maintains Linux policy routing table `200` (`ip route replace default via <WIFI_GW> dev <WIFI_IF> table 200` and `ip rule add from <WIFI_IP> lookup 200 priority 4000`, running before Tailscale's `5210..5270` and `main`'s `32766` rules).
- Every health probe socket binds both `SO_BINDTODEVICE` to `$WIFI_IF` **and** its local source address to `$WIFI_IP`.
- Outgoing probes physically leave over Wi-Fi, and incoming replies match `from $WIFI_IP lookup 200` during `fib_validate_source()`, passing strict `rp_filter=1` cleanly without touching normal system traffic.

---

## Active-Lease-Only Forwarding (`lease_hook.py` & `firewall.py`)

When `forwarding.policy = "active_leases"` (the default):
1. `PRIMARY` mode initializes `table inet lifeline` with empty `allowed_v4` (`ipv4_addr . ether_addr`) and `allowed_v6_mac` (`ether_addr`) sets (re-seeding any still-valid leases from `/run/lifeline/dnsmasq.leases`).
2. `dnsmasq` runs `/usr/local/libexec/lifeline-lease-hook` sequentially on every `add`, `old`, and `del` lease event:
   - **IPv4 `add`/`old`**: Adds `(ip . mac)` to `allowed_v4` and `mac` to `allowed_v6_mac`.
   - **IPv6 `add`/`old`**: Reads `DNSMASQ_MAC` and adds `mac` to `allowed_v6_mac` (allowing both DHCPv6 and SLAAC/privacy-extension addresses from authorized clients).
   - **`del`**: Removes `(ip . mac)` from `allowed_v4`, and removes `mac` from `allowed_v6_mac` only if no other active lease remains for that MAC.
3. Unlisted or rogue Ethernet devices cannot spoof a leased IP (because `allowed_v4` checks `(ip, mac)` together) and cannot forward IPv4 or IPv6 traffic.

---

## Repository Layout

```text
lifeline/
├── README.md                     # This architecture & maintenance guide
├── pyproject.toml                # Python packaging metadata (zero external deps)
├── install.sh                    # Ubuntu 26.04 installer (--dry-run / --uninstall)
├── config/
│   ├── config.toml.example       # Fully documented configuration reference
│   ├── config.env.example        # Optional minimal per-machine overrides (ETH_IP=...)
│   └── dhcp_hosts.csv.example    # Static MAC -> IPv4 (+ optional IPv6/hostname) table
├── systemd/
│   └── lifeline.service          # Systemd unit with cgroup kill & ExecStopPost cleanup
├── apparmor/
│   └── usr.sbin.dnsmasq.local    # AppArmor drop-in for /run/lifeline & lease hook
├── scripts/
│   └── lifeline-lease-hook       # Wrapper invoked by dnsmasq --dhcp-script
├── src/lifeline/
│   ├── config.py                 # TOML/.env/CSV parser, RFC 4193 ULA derivation, validator
│   ├── state.py                  # Pure state machine (IDLE/FAILOVER/SECONDARY/ELECTION/PRIMARY)
│   ├── probe.py                  # Policy table 200 Wi-Fi probe + raw AF_PACKET DHCP/ARP probes
│   ├── election.py               # Link-local IPv6 multicast beacon bus & rank computation
│   ├── dhcp.py                   # dnsmasq config generator, RA lifetime=0 sender, supervisor
│   ├── firewall.py               # Atomic nftables manager + optional ufw rule manager
│   ├── lease_hook.py             # dnsmasq --dhcp-script handler
│   ├── sysctl.py                 # Save/apply/restore IPv4 per-iface & IPv6 global forwarding
│   ├── net_utils.py              # Sysfs, iproute2 JSON parsing, async subprocess helpers
│   ├── daemon.py                 # Main asyncio coordinator (`lifelined`)
│   ├── cli.py                    # Operator CLI (`lifelinectl`) + fast `prompt` PS1 helper
│   ├── tray.py                   # Desktop system tray applet & mode-change notifier (`lifeline-tray`)
│   └── backends/
│       ├── base.py               # Abstract NetworkBackend
│       ├── networkmanager.py     # Ubuntu Desktop NM runtime-profile + resolvectl backend
│       └── networkd.py           # Optional Ubuntu Server systemd-networkd backend
├── shell/
│   └── lifeline-prompt.sh        # Ready-to-source bash/zsh PS1 helper
├── icons/                        # SVG tray icons (primary/secondary/failover/idle)
├── man/                          # Man pages (lifeline.8, lifelinectl.8, lifelined.8)
└── tests/
    ├── unit/                     # Pure unit tests (no root required)
    └── integration/              # Rootless/rootful Linux network namespace tests
```

---

## Installation & Operations (Ubuntu 26.04 — `arm64`, `armhf`, `i386`, `amd64`)

### Option A: Build & Install the `.deb` Package (Recommended)

Because Lifeline is pure Python 3 stdlib, `./build_deb.sh` builds a single architecture-independent package (`Architecture: all`) that works on **arm64, arm32 (armhf), x86 (i386), and x64 (amd64)**:

```bash
./build_deb.sh
# Creates dist/lifeline_0.1.0_all.deb
```

Copy `dist/lifeline_0.1.0_all.deb` to any target machine and install it with `apt` (which automatically installs `python3`, `dnsmasq-base`, `nftables`, `iproute2`, and `network-manager`):

```bash
scp dist/lifeline_0.1.0_all.deb user@laptop:/tmp/
ssh user@laptop "sudo apt update && sudo apt install -y /tmp/lifeline_0.1.0_all.deb"
```

### Option B: Direct Install from Source

```bash
sudo apt update
sudo apt install -y python3 dnsmasq-base nftables iproute2 network-manager
sudo ./install.sh
```
> Install `dnsmasq-base` (not `dnsmasq`) so no conflicting system `dnsmasq.service` binds port 53 against `systemd-resolved`.

### 3. Configure per-machine settings
- Edit `/etc/lifeline/config.toml` (all parameters are documented inline) or set per-machine overrides in `/etc/lifeline/config.env` (`ETH_IP=192.168.9.24/24`, `ELECTION_PRIORITY=100`).
- Populate `/etc/lifeline/dhcp_hosts.csv` with your client MAC addresses and static IPs. (If you want laptops in `FAILOVER` mode to also get IPs from whichever laptop is `PRIMARY`, include the laptops' Ethernet MACs in the table as well.)

### 4. Validate, Start & Inspect
```bash
sudo lifelinectl validate
sudo systemctl start lifeline
sudo lifelinectl status
```

### 5. Common Operator Commands
```bash
sudo lifelinectl status --json           # Machine-readable live status, peers, and leases
sudo lifelinectl reload                  # Hot-reload config.toml & dhcp_hosts.csv (SIGHUP)
sudo lifelinectl force-mode failover     # Temporarily force FAILOVER mode for testing
sudo lifelinectl force-mode auto         # Return to automatic mode
sudo nft list table inet lifeline        # Inspect live nftables sets & packet counters
journalctl -u lifeline -f                # Stream daemon logs
```

---

## Testing

### Unit Tests (no root required)
```bash
PYTHONPATH=src python3 -m unittest discover -s tests/unit -v
```

### End-to-End Namespace Integration Tests
See `tests/integration/README.md` for running the self-contained Linux network namespace (`unshare` / `ip netns`) test suite with real `dnsmasq`, `nftables`, `DHCPDISCOVER` probes, IPv4/IPv6 forwarding, and strict `rp_filter=1` recovery verification.

---

## Contributing, Bug Fixes & Feature Improvements

Bug fixes, edge-case hardening, and feature improvements are warmly encouraged!
If you encounter unexpected behavior with a specific Wi-Fi/Ethernet driver, USB-C NIC, NetworkManager/systemd-networkd version, or multi-laptop failover scenario, please include `sudo lifelinectl status --json` and `journalctl -u lifeline` output alongside your patch or issue report, and run `PYTHONPATH=src python3 -m unittest discover -s tests/unit -v` before submitting changes.

## Author & License

- **Author:** Vikram Aggarwal
- **License:** GNU General Public License v3.0 or later (GPLv3). See [LICENSE](LICENSE) for the full text.
