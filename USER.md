# Lifeline User & Operator Guide

This guide is for anyone using or troubleshooting a Linux laptop where **Lifeline** is already installed. It explains how to tell **at a glance** what mode the laptop is in, **whether it is serving DHCP clients (and which ones)**, and **how to inspect logs and state transitions** when something isn't behaving as expected.

---

## 1. Quick Check: Is This Laptop Serving DHCP Clients Right Now?

Run:

```bash
sudo lifelinectl status
```

Look at the very first line (`Mode: ...`):

| `Mode` | What this laptop is doing right now | Serving DHCP clients? |
| :--- | :--- | :--- |
| **`PRIMARY`** | Wi-Fi is healthy and this laptop owns the Ethernet segment (`eth_ip`, e.g. `192.168.9.24/24`). `dnsmasq` is running and forwarding IPv4/IPv6 for active DHCP clients over Wi-Fi. | **YES** |
| **`SECONDARY`** | Wi-Fi is healthy, **but another DHCP server is already active** on the Ethernet wire (either an upstream hardware router or another Lifeline laptop in `PRIMARY` mode). This laptop stays on standby and uses Wi-Fi for its own internet. | **NO** (another server is primary) |
| **`FAILOVER`** | Wi-Fi connectivity failed. Lifeline stopped `dnsmasq`, blocked Ethernet forwarding, and configured Ethernet as a **DHCP client** to use the upstream Ethernet gateway and DNS. | **NO** (Ethernet is a DHCP client) |
| **`ELECTION`** | Wi-Fi is healthy and no active primary DHCP server was found; waiting a short rank-based backoff (`0.5s + rank * rank_backoff_sec`) before promoting to `PRIMARY`. | **NO** (promoting shortly) |
| **`IDLE`** | The Ethernet cable is unplugged (`carrier=False`). | **NO** (no Ethernet link) |

You can also see a one-line status directly from systemd without calling `lifelinectl`:

```bash
systemctl status lifeline --no-pager
```

Look for the `Status:` line (e.g., `Status: "Mode: PRIMARY (won election ...)"`), or inspect the JSON snapshot written every second to `/run/lifeline/status.json` (`sudo lifelinectl status --json`).

---

## 2. Seeing Which DHCP Clients Are Being Served (and Forwarded)

When `Mode` is `PRIMARY`, `sudo lifelinectl status` prints all active leases under `Active Leases (N):`:

```text
Node: laptop-01   Mode: PRIMARY   Reason: won election (rank 0, waited 0.5s)
Interfaces: eth=enp0s31f6 (carrier=True, mac=aa:11:22:33:44:55)  wifi=wlp0s20f3 (mac=bb:11:22:33:44:55)
LAN: ipv4=192.168.9.24/24  ipv6=fdf3:b87d:f74d::24/64 (ula_nat66)
Wi-Fi Health: ok=True (v4=True v6=False)  ok_streak=120  fail_streak=0
Election: priority=100  ext_dhcp=False (None)  peers=2
  peer laptop-02 (aa:11:22:33:44:66): state=SECONDARY prio=100 wifi_ok=True
  peer laptop-03 (aa:11:22:33:44:77): state=SECONDARY prio=100 wifi_ok=True
Active Leases (2):
  aa:bb:cc:dd:ee:01 -> 192.168.9.101 (device-alpha)
  aa:bb:cc:dd:ee:02 -> 192.168.9.102 (device-beta)
```

### Three places to cross-check client leases and forwarding

1. **Active DHCP lease file** (maintained by the managed `dnsmasq` child process):
   ```bash
   cat /run/lifeline/dnsmasq.leases
   ```
   Each line has `<expiry_epoch> <mac> <ip> <hostname> <client_id>`.

2. **Allowed MAC-to-IP configuration table** (only listed MACs are given leases):
   ```bash
   cat /etc/lifeline/dhcp_hosts.csv
   ls /etc/lifeline/hosts.d/
   ```

3. **Kernel `nftables` forwarding allowlist** (which clients are actually permitted to forward traffic right now):
   ```bash
   sudo nft list table inet lifeline
   ```
   - In `PRIMARY` mode, `set allowed_v4` lists `ip . mac` pairs and `set allowed_v6_mac` lists authorized MACs.
   - In `SECONDARY`, `FAILOVER`, or `IDLE` mode, the `forward` chain contains only `iifname "<eth>" drop` and `oifname "<eth>" drop` (zero forwarding, zero NAT).

---

## 3. Finding State Changes and Troubleshooting in the Logs

Lifeline does **not** write a separate log file under `/var/log/`. All logs go to **`systemd-journald`** (and to `/var/log/syslog` if `rsyslog` is installed).

### View all Lifeline state changes

```bash
# Full Lifeline log history (newest at bottom)
journalctl -u lifeline --no-pager

# Filter ONLY state transitions (shows every mode change and why it happened)
journalctl -u lifeline | grep "Transitioning"

# Watch live as you unplug Wi-Fi, unplug Ethernet, or test failover
journalctl -u lifeline -f
```

Example transition log lines:

```text
[INFO] lifeline.daemon: Transitioning None -> FAILOVER (startup safe default)
[INFO] lifeline.daemon: Transitioning FAILOVER -> ELECTION (Wi-Fi recovered and no DHCP server active -> ELECTION)
[INFO] lifeline.daemon: Transitioning ELECTION -> PRIMARY (won election (rank 0, waited 0.5s))
[INFO] lifeline.daemon: Transitioning PRIMARY -> FAILOVER (Wi-Fi failed (3 consecutive failures))
[INFO] lifeline.daemon: Transitioning FAILOVER -> SECONDARY (Wi-Fi recovered; existing DHCP server active -> SECONDARY)
```

### View DHCP server (`dnsmasq`) logs

When Lifeline is in `PRIMARY` mode, `dnsmasq` is started with `log-dhcp` enabled. Its `DHCPDISCOVER`, `DHCPOFFER`, `DHCPREQUEST`, and `DHCPACK` messages are logged under the `dnsmasq` syslog identifier:

```bash
journalctl -t dnsmasq --no-pager
journalctl -t dnsmasq -f
```

If a client plugs in and is **ignored** (`no address available` or silent ignore because it's not in `/etc/lifeline/dhcp_hosts.csv`), it will show up here.

### View logs since a specific time or boot

```bash
journalctl -u lifeline -b                # Current boot only
journalctl -u lifeline --since "1 hour ago"
journalctl -u lifeline -u NetworkManager --since "15 min ago"
```

### Enable verbose (`DEBUG`) logging temporarily

If you need to see every probe result (`DHCPDISCOVER` replies, `BeaconBus` messages, `arping` checks):

```bash
sudo systemctl edit lifeline
```

Add:

```ini
[Service]
Environment=LIFELINE_LOG_LEVEL=DEBUG
```

Then restart:

```bash
sudo systemctl restart lifeline
journalctl -u lifeline -f
```

---

## 4. Common "Why Isn't It Serving DHCP?" Scenarios

| Symptom in `lifelinectl status` / Logs | Meaning | What to Check |
| :--- | :--- | :--- |
| `Mode: SECONDARY` + `ext_dhcp=True (<ip> (<mac>))` | Another DHCP server (upstream router or another laptop) answered `DHCPDISCOVER` on Ethernet. | Normal standby behavior; if unexpected, check what device at `<ip>` / `<mac>` is serving DHCP on the switch. |
| `Mode: SECONDARY` + `peers` shows another `PRIMARY` | Another Lifeline laptop with lower `(priority, mac)` owns the wire. | Normal multi-laptop behavior. To prefer this laptop, lower `priority` in `/etc/lifeline/config.toml` (or `ELECTION_PRIORITY` in `/etc/lifeline/config.env`) and `sudo systemctl restart lifeline`. |
| Log shows `Aborting PRIMARY promotion: ARP conflict for 192.168.9.24` | Another machine on the Ethernet switch already holds `ETH_IP`. | Check the conflicting MAC printed in the log and verify `/etc/lifeline/config.toml` or `/etc/lifeline/config.env`. |
| `Mode: FAILOVER` even though Wi-Fi icon looks connected | Wi-Fi is associated to an AP, but Lifeline's Wi-Fi-bound probe cannot reach `health.ipv4_targets` / `ipv6_targets` over Wi-Fi (`wifi_probe_ok=False`). | Check `Wi-Fi Health:` in `lifelinectl status`. On an isolated intranet with no public internet, set `mode = "gateway"` in `[health]`. |
| `Mode: IDLE` | Linux reports `carrier=False` on Ethernet. | Check the Ethernet cable/switch port or USB-C dongle (`ip link show dev <eth>`). |
| `Mode: PRIMARY`, but a device didn't get an IP | The device's MAC is missing from `/etc/lifeline/dhcp_hosts.csv` (Lifeline only serves listed MACs). | Add `<mac>,<ip>,<hostname>,` to `/etc/lifeline/dhcp_hosts.csv`, validate with `sudo lifelinectl validate`, and apply live with `sudo lifelinectl reload`. |

---

## 5. Shell Prompt (`PS1`), Desktop Tray & Everyday Operator Commands

### Fast Shell Prompt Status (`bash` / `zsh`)

`lifelinectl prompt` reads `/run/lifeline/status.json` directly (no `sudo` or socket wait) and outputs a compact badge such as `[LL:PRI(2)]`, `[LL:SEC]`, `[LL:FAIL]`, or `[LL:IDLE]`:

```bash
# ~/.bashrc
source /usr/share/lifeline/shell/lifeline-prompt.sh
PS1='$(lifeline_ps1 --bash --color) \u@\h:\w\$ '
```

```zsh
# ~/.zshrc
source /usr/share/lifeline/shell/lifeline-prompt.sh
setopt PROMPT_SUBST
PROMPT='$(lifeline_ps1 --zsh --color) %n@%m:%~%# '
```

### Desktop Tray Applet (`lifeline-tray`)

On Ubuntu Desktop, the `.deb` registers `/etc/xdg/autostart/lifeline-tray.desktop` automatically (requires optional `python3-gi` and `gir1.2-ayatanaappindicatorglib-2.0`, or falls back to `notify-send` popups). Run `lifeline-tray` manually to start it in the current session.

### Everyday Operator Commands

```bash
sudo lifelinectl status                 # Human-readable status, uplinks, RTT, peers, and leases
sudo lifelinectl doctor                 # Full startup & network-manager environment diagnostics
sudo lifelinectl validate               # Check config.toml, config.env, and dhcp_hosts.csv
sudo lifelinectl reload                 # Reload config & MAC table live (SIGHUP, no restart)
sudo lifelinectl force-mode failover    # Force FAILOVER mode for testing
sudo lifelinectl force-mode primary     # Force PRIMARY mode for testing
sudo lifelinectl force-mode auto        # Return to automatic mode
lifelinectl prompt --color              # Compact one-shot badge for scripts/prompts
```

---

## 6. Feedback, Bug Fixes & Feature Improvements

Bug reports, bug fixes, and feature improvements are warmly encouraged! If you hit an issue on your machine, attach the output of `sudo lifelinectl status --json` and `journalctl -u lifeline -b` so maintainers can diagnose and improve Lifeline.

**Author:** Vikram Aggarwal  
**License:** GNU General Public License v3.0 or later (GPLv3; see `/usr/share/doc/lifeline/LICENSE` or `LICENSE`).
