# 🧅 Tor Control Center

A professional system tray application for monitoring and controlling Tor on Linux (KDE/GNOME). Shows real-time connection status, exit node info, latency, and provides one-click controls.

![status](https://img.shields.io/badge/status-stable-brightgreen)
![platform](https://img.shields.io/badge/platform-Linux-blue)
![python](https://img.shields.io/badge/python-3.10%2B-yellow)

---

## Features

- **Real connection check** — verifies actual routing through Tor (via check.torproject.org), not just whether the service is running
- **GeoIP info** — country, ISP/org of the current exit node
- **Latency measurement** — round-trip time through the Tor circuit
- **Leak detection** — compares your direct IP against the Tor exit IP
- **One-click controls** — Start / Stop / Restart Tor, request a New Identity
- **Kill switch** — blocks all non-Tor traffic via iptables if Tor goes down
- **Transparent proxy toggle** — route all system TCP/DNS traffic through Tor
- **System tray integration** — color-coded icon (green/yellow/red) with live tooltip
- **Event log** — rolling log of state changes inside the dashboard

---

## Screenshots

*(add your own screenshots here)*

---

## Requirements

- Linux with a system tray (KDE Plasma, GNOME with extension, XFCE, etc.)
- Python 3.10+
- `tor` package
- `PyQt6`
- `requests` with SOCKS support

---

## Installation

```bash
git clone https://github.com/dev4ref/tor-control-center.git
cd tor-control-center
chmod +x setup.sh
./setup.sh
```

The setup script will:

- Install `tor`, `PyQt6`, and `requests[socks]`
- Add a sudoers rule so Tor and `iptables` can be controlled without a password prompt each time
- Copy the script to `~/.local/bin/tor_tray.py`
- Create an autostart entry (tray only — **Tor itself stays off** until you start it manually)
- Create an application launcher entry

> **Note:** Tor is *not* enabled to autostart with the system. The app starts in the tray on login, shows 🔴 disconnected, and you connect manually via the **▶ Start** button. To change this, see [Manual vs Automatic Tor](#manual-vs-automatic-tor) below.

---

## Usage

```bash
python3 ~/.local/bin/tor_tray.py
```

Click the tray icon to open the dashboard. Buttons:

| Button | Action |
|---|---|
| ▶ Start | `systemctl start tor` |
| ■ Stop | `systemctl stop tor` |
| ↺ Restart | `systemctl restart tor` |
| ⟳ New Identity | Requests a new circuit via the Tor control port |
| 🔒 Kill Switch | Toggles iptables rules that block all non-Tor traffic |
| ⬡ Transparent | Toggles system-wide transparent proxying through Tor |
| ⟳ Check Now | Forces an immediate status probe |

---

## Manual vs Automatic Tor

By default, Tor does **not** start with the system — only the tray monitor does.

**To keep it manual (default):**
```bash
sudo systemctl disable tor
```

**To have Tor start automatically with the system:**
```bash
sudo systemctl enable tor
```

---

## New Identity / Control Port

To enable the "New Identity" feature via the control port, add to `/etc/tor/torrc`:

```
ControlPort 9051
CookieAuthentication 0
```

Then:
```bash
sudo systemctl restart tor
```

> If the control port isn't configured, "New Identity" falls back to restarting the Tor service.

---

## Transparent Proxy (system-wide tunneling)

The "Transparent" button redirects all outbound TCP and DNS traffic through Tor's `TransPort`/`DNSPort`. For this to work, add to `/etc/tor/torrc`:

```
TransPort 9040
DNSPort 5353
AutomapHostsOnResolve 1
```

Then restart Tor. Toggle the button in the dashboard to enable/disable the iptables redirection rules.

---

## Uninstall

```bash
rm ~/.local/bin/tor_tray.py
rm ~/.config/autostart/tor-control-center.desktop
rm ~/.local/share/applications/tor-control-center.desktop
sudo rm /etc/sudoers.d/tor-control-center
```

---

## License

MIT — see [LICENSE](LICENSE)

## Disclaimer

This tool manages your local Tor daemon and firewall rules. It does not provide anonymity guarantees beyond what Tor itself provides. Review the iptables rules in `tor_tray.py` before relying on the kill switch or transparent proxy for sensitive use cases.
