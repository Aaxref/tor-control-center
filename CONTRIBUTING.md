# Contributing

Contributions are welcome.

## Setup

```bash
git clone https://github.com/yourusername/tor-control-center.git
cd tor-control-center
pip3 install -r requirements.txt --break-system-packages
python3 tor_tray.py
```

## Guidelines

- Keep the dependency list minimal (PyQt6, requests).
- Match the existing code style (dataclasses for state, signals/slots for thread → UI communication).
- Test changes to `TorControl` carefully — these run `sudo` commands and modify `iptables`.
- Open an issue before large changes to the iptables logic.

## Reporting issues

Please include:
- Distro and desktop environment (KDE, GNOME, etc.)
- Output of `systemctl status tor`
- Output of `python3 tor_tray.py` run from a terminal
