#!/usr/bin/env python3
"""
🧅 Tor Control Center v2
Professional KDE/GNOME system tray — real Tor monitoring & control
Author: tor_tray v2
Requires: python3-pyqt6, requests[socks]
"""

from __future__ import annotations

import os
import sys
import json
import time
import socket
import subprocess
import threading
import logging
from datetime import datetime
from collections import deque
from dataclasses import dataclass, field
from typing import Optional

# ── Enforce PyQt6 ─────────────────────────────────────────────────────────────
try:
    from PyQt6.QtWidgets import (
        QApplication, QSystemTrayIcon, QMenu, QWidget,
        QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
        QTextEdit, QFrame, QGridLayout, QSizePolicy,
    )
    from PyQt6.QtCore import (
        Qt, QTimer, QThread, pyqtSignal, QObject, QSize, QPoint,
    )
    from PyQt6.QtGui import (
        QIcon, QPixmap, QPainter, QColor, QFont, QBrush,
        QPen, QAction, QFontMetrics,
    )
except ImportError:
    print("ERROR: PyQt6 not found.\n  pip3 install PyQt6 --break-system-packages")
    sys.exit(1)

try:
    import requests
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False
    print("WARNING: requests not found.  pip3 install requests[socks]")

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("tor_tray")

# ── Constants ─────────────────────────────────────────────────────────────────
TOR_SOCKS_HOST    = "127.0.0.1"
TOR_SOCKS_PORT    = 9050
TOR_CONTROL_PORT  = 9051
TOR_TRANS_PORT    = 9040
TOR_DNS_PORT      = 5353

TOR_CHECK_URL     = "https://check.torproject.org/api/ip"
GEOIP_URL         = "http://ip-api.com/json/{ip}?fields=status,country,countryCode,isp,org,query"
DIRECT_IP_URL     = "https://api.ipify.org?format=json"

POLL_NORMAL_SEC   = 8
POLL_FAST_SEC     = 2
REQUEST_TIMEOUT   = 10
LOG_MAXLEN        = 300

# ── Palette ───────────────────────────────────────────────────────────────────
P = {
    "bg":        "#0d1117",
    "surface":   "#161b22",
    "surface2":  "#21262d",
    "border":    "#30363d",
    "green":     "#3fb950",
    "purple":    "#a371f7",
    "orange":    "#f0883e",
    "red":       "#f85149",
    "blue":      "#58a6ff",
    "text":      "#e6edf3",
    "muted":     "#8b949e",
    "dim":       "#484f58",
}

# ── State dataclass ───────────────────────────────────────────────────────────
@dataclass
class TorState:
    mode:          str   = "init"       # init | disconnected | connecting | connected | leak
    tor_running:   bool  = False
    socks_up:      bool  = False
    is_tor_exit:   bool  = False
    exit_ip:       str   = "—"
    real_ip:       str   = "—"
    country:       str   = "—"
    country_code:  str   = ""
    isp:           str   = "—"
    latency_ms:    Optional[int] = None
    leak:          bool  = False
    ts:            str   = ""
    error:         str   = ""

    def flag(self) -> str:
        cc = self.country_code
        if len(cc) != 2:
            return "🌐"
        return chr(0x1F1E6 + ord(cc[0]) - 65) + chr(0x1F1E6 + ord(cc[1]) - 65)

    def mode_label(self) -> str:
        return {
            "init":         "Initializing…",
            "disconnected": "Disconnected",
            "connecting":   "Building circuit…",
            "connected":    "Connected via Tor",
            "leak":         "IP LEAK DETECTED",
        }.get(self.mode, self.mode.upper())

    def mode_color(self) -> str:
        return {
            "init":         P["muted"],
            "disconnected": P["red"],
            "connecting":   P["orange"],
            "connected":    P["green"],
            "leak":         P["red"],
        }.get(self.mode, P["muted"])


# ══════════════════════════════════════════════════════════════════════════════
#  TorProbe  — all network checks, runs in background thread
# ══════════════════════════════════════════════════════════════════════════════
class TorProbe(QObject):
    state_ready = pyqtSignal(object)   # TorState
    log_line    = pyqtSignal(str, str) # level, message

    def __init__(self) -> None:
        super().__init__()
        self._active  = False
        self._thread: Optional[threading.Thread] = None

    # ── lifecycle ─────────────────────────────────────────────────────────────
    def start(self) -> None:
        self._active = True
        self._thread = threading.Thread(target=self._loop, daemon=True, name="TorProbe")
        self._thread.start()

    def stop(self) -> None:
        self._active = False

    def probe_now(self) -> None:
        """Trigger an immediate out-of-cycle probe."""
        t = threading.Thread(target=self._single_probe, daemon=True)
        t.start()

    # ── main loop ─────────────────────────────────────────────────────────────
    def _loop(self) -> None:
        while self._active:
            state = self._single_probe()
            interval = POLL_FAST_SEC if state.mode in ("connecting", "init") else POLL_NORMAL_SEC
            time.sleep(interval)

    def _single_probe(self) -> TorState:
        s = TorState(ts=datetime.now().strftime("%H:%M:%S"))
        try:
            s.tor_running = self._service_running()
            s.socks_up    = self._socks_reachable()

            if not s.tor_running and not s.socks_up:
                s.mode = "disconnected"
                self.state_ready.emit(s)
                return s

            if not s.socks_up:
                s.mode = "connecting"
                self.state_ready.emit(s)
                return s

            # Check routing via Tor
            tor_check = self._tor_check()
            if tor_check is None:
                s.mode = "connecting"
                self.state_ready.emit(s)
                return s

            s.exit_ip     = tor_check.get("IP", "—")
            s.is_tor_exit = tor_check.get("IsTor", False)

            # Real IP (direct)
            s.real_ip = self._direct_ip() or "—"

            # Leak detection
            if s.real_ip != "—" and s.exit_ip != "—":
                s.leak = (s.real_ip == s.exit_ip)

            # GeoIP on exit node
            if s.exit_ip != "—":
                geo = self._geoip(s.exit_ip)
                s.country      = geo.get("country", "—")
                s.country_code = geo.get("countryCode", "")
                s.isp          = geo.get("isp") or geo.get("org", "—")

            # Latency
            s.latency_ms = self._latency()

            # Final mode
            if s.leak:
                s.mode = "leak"
                self.log_line.emit("WARN", f"IP LEAK: real={s.real_ip}  exit={s.exit_ip}")
            elif s.is_tor_exit:
                s.mode = "connected"
            else:
                s.mode = "connecting"

        except Exception as exc:
            s.mode  = "disconnected"
            s.error = str(exc)
            log.exception("Probe error")

        self.state_ready.emit(s)
        return s

    # ── checks ────────────────────────────────────────────────────────────────
    @staticmethod
    def _service_running() -> bool:
        # systemctl
        try:
            r = subprocess.run(
                ["systemctl", "is-active", "--quiet", "tor"],
                timeout=3
            )
            if r.returncode == 0:
                return True
        except Exception:
            pass
        # pgrep fallback
        try:
            r = subprocess.run(["pgrep", "-x", "tor"], capture_output=True, timeout=3)
            return r.returncode == 0
        except Exception:
            return False

    @staticmethod
    def _socks_reachable() -> bool:
        try:
            with socket.create_connection((TOR_SOCKS_HOST, TOR_SOCKS_PORT), timeout=2):
                return True
        except OSError:
            return False

    @staticmethod
    def _tor_check() -> Optional[dict]:
        if not _HAS_REQUESTS:
            return None
        proxies = {
            "http":  f"socks5h://{TOR_SOCKS_HOST}:{TOR_SOCKS_PORT}",
            "https": f"socks5h://{TOR_SOCKS_HOST}:{TOR_SOCKS_PORT}",
        }
        try:
            r = requests.get(TOR_CHECK_URL, proxies=proxies, timeout=REQUEST_TIMEOUT)
            r.raise_for_status()
            return r.json()
        except Exception:
            return None

    @staticmethod
    def _direct_ip() -> Optional[str]:
        if not _HAS_REQUESTS:
            return None
        try:
            r = requests.get(DIRECT_IP_URL, timeout=5)
            r.raise_for_status()
            return r.json().get("ip")
        except Exception:
            return None

    @staticmethod
    def _geoip(ip: str) -> dict:
        if not _HAS_REQUESTS:
            return {}
        try:
            r = requests.get(GEOIP_URL.format(ip=ip), timeout=5)
            r.raise_for_status()
            data = r.json()
            return data if data.get("status") == "success" else {}
        except Exception:
            return {}

    @staticmethod
    def _latency() -> Optional[int]:
        if not _HAS_REQUESTS:
            return None
        proxies = {
            "http":  f"socks5h://{TOR_SOCKS_HOST}:{TOR_SOCKS_PORT}",
            "https": f"socks5h://{TOR_SOCKS_HOST}:{TOR_SOCKS_PORT}",
        }
        try:
            t0 = time.monotonic()
            requests.get("https://check.torproject.org/", proxies=proxies, timeout=REQUEST_TIMEOUT)
            return int((time.monotonic() - t0) * 1000)
        except Exception:
            return None


# ══════════════════════════════════════════════════════════════════════════════
#  TorControl  — subprocess-based service & firewall control
# ══════════════════════════════════════════════════════════════════════════════
class TorControl:

    @staticmethod
    def _run(*args: str) -> tuple[bool, str]:
        try:
            r = subprocess.run(
                list(args), capture_output=True, text=True, timeout=15
            )
            out = (r.stdout + r.stderr).strip()
            return r.returncode == 0, out
        except Exception as e:
            return False, str(e)

    @classmethod
    def start(cls)   -> tuple[bool, str]: return cls._run("sudo","systemctl","start","tor")
    @classmethod
    def stop(cls)    -> tuple[bool, str]: return cls._run("sudo","systemctl","stop","tor")
    @classmethod
    def restart(cls) -> tuple[bool, str]: return cls._run("sudo","systemctl","restart","tor")

    @classmethod
    def new_identity(cls) -> tuple[bool, str]:
        """Send NEWNYM via control port, fall back to restart."""
        try:
            s = socket.socket()
            s.settimeout(4)
            s.connect(("127.0.0.1", TOR_CONTROL_PORT))
            s.sendall(b'AUTHENTICATE ""\r\nSIGNAL NEWNYM\r\nQUIT\r\n')
            resp = s.recv(512).decode(errors="replace")
            s.close()
            if "250" in resp:
                return True, "New circuit requested via control port"
            return False, f"Control port response: {resp}"
        except Exception as e:
            log.warning(f"Control port failed ({e}), falling back to restart")
            return cls.restart()

    @classmethod
    def killswitch_on(cls) -> tuple[bool, str]:
        """Block all non-Tor outbound traffic via iptables."""
        cmds = [
            ["sudo", "iptables", "-t", "nat", "-F", "OUTPUT"],
            ["sudo", "iptables", "-F", "OUTPUT"],
            # Allow loopback
            ["sudo", "iptables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"],
            # Allow Tor process itself
            ["sudo", "iptables", "-A", "OUTPUT", "-m", "owner",
             "--uid-owner", "debian-tor", "-j", "ACCEPT"],
            # Allow established connections
            ["sudo", "iptables", "-A", "OUTPUT", "-m", "state",
             "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
            # Reject everything else
            ["sudo", "iptables", "-A", "OUTPUT", "-j", "REJECT"],
        ]
        for cmd in cmds:
            ok, out = cls._run(*cmd)
            if not ok:
                return False, f"iptables error: {out}"
        return True, "Kill switch ON — non-Tor traffic blocked"

    @classmethod
    def killswitch_off(cls) -> tuple[bool, str]:
        """Remove kill switch rules."""
        ok1, o1 = cls._run("sudo", "iptables", "-F", "OUTPUT")
        ok2, o2 = cls._run("sudo", "iptables", "-t", "nat", "-F", "OUTPUT")
        return (ok1 and ok2), f"{o1} {o2}".strip()

    @classmethod
    def transparent_proxy_on(cls) -> tuple[bool, str]:
        """Route all TCP + DNS through Tor transparently."""
        cmds = [
            # DNS → Tor DNS port
            ["sudo", "iptables", "-t", "nat", "-A", "OUTPUT",
             "-p", "udp", "--dport", "53",
             "-j", "REDIRECT", "--to-ports", str(TOR_DNS_PORT)],
            # TCP → Tor TransPort (exempt Tor itself)
            ["sudo", "iptables", "-t", "nat", "-A", "OUTPUT",
             "-m", "owner", "--uid-owner", "debian-tor", "-j", "RETURN"],
            ["sudo", "iptables", "-t", "nat", "-A", "OUTPUT",
             "-p", "tcp", "--syn",
             "-j", "REDIRECT", "--to-ports", str(TOR_TRANS_PORT)],
        ]
        for cmd in cmds:
            ok, out = cls._run(*cmd)
            if not ok:
                return False, f"iptables error: {out}"
        return True, "Transparent proxy ON — all TCP/DNS tunnelled"

    @classmethod
    def transparent_proxy_off(cls) -> tuple[bool, str]:
        ok, out = cls._run("sudo", "iptables", "-t", "nat", "-F", "OUTPUT")
        return ok, out or "Transparent proxy OFF"


# ══════════════════════════════════════════════════════════════════════════════
#  Icons
# ══════════════════════════════════════════════════════════════════════════════
def _make_icon(mode: str, size: int = 22) -> QIcon:
    color_map = {
        "connected":    P["green"],
        "connecting":   P["orange"],
        "disconnected": P["red"],
        "leak":         P["red"],
        "init":         P["muted"],
    }
    color = QColor(color_map.get(mode, P["muted"]))

    px = QPixmap(size, size)
    px.fill(Qt.GlobalColor.transparent)
    p  = QPainter(px)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)

    # Ring
    pen = QPen(color, 2.2)
    p.setPen(pen)
    p.setBrush(Qt.BrushStyle.NoBrush)
    p.drawEllipse(2, 2, size - 4, size - 4)

    # Inner state
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QBrush(color))
    c = size // 2
    if mode == "connected":
        r = size // 5
        p.drawEllipse(c - r, c - r, r * 2, r * 2)
    elif mode == "connecting":
        r = size // 6
        p.drawEllipse(c - r, c - r, r * 2, r * 2)
    elif mode in ("disconnected", "leak"):
        pen2 = QPen(color, 2.5)
        p.setPen(pen2)
        m = size // 4
        p.drawLine(m, m, size - m, size - m)
        p.drawLine(size - m, m, m, size - m)

    p.end()
    return QIcon(px)


# ══════════════════════════════════════════════════════════════════════════════
#  Dashboard  — main popup window
# ══════════════════════════════════════════════════════════════════════════════
class Dashboard(QWidget):

    def __init__(self, probe: TorProbe) -> None:
        super().__init__()
        self.probe = probe
        self._ks_on    = False
        self._tp_on    = False
        self._drag_pos: Optional[QPoint] = None
        self._log_buf: deque[str] = deque(maxlen=LOG_MAXLEN)

        self.setWindowTitle("Tor Control Center")
        self.setFixedSize(460, 600)
        self.setWindowFlags(
            Qt.WindowType.Window |
            Qt.WindowType.FramelessWindowHint |
            Qt.WindowType.WindowStaysOnTopHint
        )
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)

        self._build()
        self._style()

    # ── build ─────────────────────────────────────────────────────────────────
    def _build(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)

        self._card = QFrame(self)
        self._card.setObjectName("card")
        self._card.setFixedSize(460, 600)
        root.addWidget(self._card)

        lay = QVBoxLayout(self._card)
        lay.setContentsMargins(18, 14, 18, 14)
        lay.setSpacing(10)

        # ── title bar ─────────────────────────────────────────────────────────
        tb = QHBoxLayout()
        onion = QLabel("🧅")
        onion.setFont(QFont("Noto Emoji", 18))
        title = QLabel("Tor Control Center")
        title.setObjectName("title")
        self._close = QPushButton("✕")
        self._close.setObjectName("closeBtn")
        self._close.setFixedSize(24, 24)
        self._close.clicked.connect(self.hide)
        tb.addWidget(onion)
        tb.addSpacing(6)
        tb.addWidget(title)
        tb.addStretch()
        tb.addWidget(self._close)
        lay.addLayout(tb)

        # ── status banner ─────────────────────────────────────────────────────
        banner = QFrame()
        banner.setObjectName("banner")
        banner.setFixedHeight(58)
        bl = QHBoxLayout(banner)
        bl.setContentsMargins(14, 6, 14, 6)

        self._dot   = QLabel("●")
        self._dot.setFont(QFont("Monospace", 18))
        self._mode  = QLabel("Initializing…")
        self._mode.setObjectName("modeLabel")
        self._ts    = QLabel("")
        self._ts.setObjectName("tsLabel")
        self._ts.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)

        bl.addWidget(self._dot)
        bl.addSpacing(8)
        bl.addWidget(self._mode, 1)
        bl.addWidget(self._ts)
        lay.addWidget(banner)

        # ── info grid ─────────────────────────────────────────────────────────
        grid_frame = QFrame()
        grid_frame.setObjectName("surface")
        grid = QGridLayout(grid_frame)
        grid.setContentsMargins(12, 8, 12, 8)
        grid.setHorizontalSpacing(12)
        grid.setVerticalSpacing(6)

        def row(label: str, r: int) -> QLabel:
            k = QLabel(label)
            k.setObjectName("key")
            v = QLabel("—")
            v.setObjectName("val")
            v.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            grid.addWidget(k, r, 0)
            grid.addWidget(v, r, 1)
            return v

        self._v_exit    = row("Exit Node",   0)
        self._v_real    = row("Real IP",     1)
        self._v_country = row("Country",     2)
        self._v_isp     = row("ISP / Org",   3)
        self._v_latency = row("Latency",     4)
        self._v_route   = row("Route",       5)
        lay.addWidget(grid_frame)

        # ── controls ──────────────────────────────────────────────────────────
        g = QGridLayout()
        g.setSpacing(7)

        self._b_start   = self._mk_btn("▶  Start",          "green",  self._act_start)
        self._b_stop    = self._mk_btn("■  Stop",           "red",    self._act_stop)
        self._b_restart = self._mk_btn("↺  Restart",        "blue",   self._act_restart)
        self._b_newid   = self._mk_btn("⟳  New Identity",  "purple", self._act_newid)
        self._b_ks      = self._mk_btn("🔒  Kill Switch",   "orange", self._act_ks)
        self._b_tp      = self._mk_btn("⬡  Transparent",   "teal",   self._act_tp)
        self._b_probe   = self._mk_btn("⟳  Check Now",     "dim",    self._act_probe)

        g.addWidget(self._b_start,   0, 0)
        g.addWidget(self._b_stop,    0, 1)
        g.addWidget(self._b_restart, 1, 0)
        g.addWidget(self._b_newid,   1, 1)
        g.addWidget(self._b_ks,      2, 0)
        g.addWidget(self._b_tp,      2, 1)
        g.addWidget(self._b_probe,   3, 0, 1, 2)
        lay.addLayout(g)

        # ── log ───────────────────────────────────────────────────────────────
        hdr = QLabel("◆  Event Log")
        hdr.setObjectName("sectionHdr")
        lay.addWidget(hdr)

        self._log = QTextEdit()
        self._log.setObjectName("logBox")
        self._log.setReadOnly(True)
        self._log.setFixedHeight(100)
        lay.addWidget(self._log)

        # drag support on card
        self._card.mousePressEvent   = self._mp
        self._card.mouseMoveEvent    = self._mm
        self._card.mouseReleaseEvent = self._mr

    def _mk_btn(self, text: str, variant: str, slot) -> QPushButton:
        b = QPushButton(text)
        b.setObjectName(f"btn_{variant}")
        b.setFixedHeight(34)
        b.setCursor(Qt.CursorShape.PointingHandCursor)
        b.clicked.connect(slot)
        return b

    # ── style ─────────────────────────────────────────────────────────────────
    def _style(self) -> None:
        self.setStyleSheet(f"""
        * {{
            font-family: 'JetBrains Mono', 'Fira Code', 'Consolas', 'Courier New', monospace;
            font-size: 12px;
            color: {P['text']};
        }}
        #card {{
            background: {P['bg']};
            border: 1px solid {P['border']};
            border-radius: 14px;
        }}
        #title {{
            font-size: 14px;
            font-weight: 700;
            letter-spacing: 0.5px;
        }}
        #closeBtn {{
            background: transparent;
            border: none;
            color: {P['muted']};
            font-size: 13px;
            border-radius: 5px;
            padding: 0;
        }}
        #closeBtn:hover {{ background: {P['red']}; color: white; }}

        #banner {{
            background: {P['surface']};
            border: 1px solid {P['border']};
            border-radius: 9px;
        }}
        #modeLabel {{ font-size: 14px; font-weight: 700; }}
        #tsLabel   {{ color: {P['muted']}; font-size: 10px; }}

        #surface {{
            background: {P['surface']};
            border: 1px solid {P['border']};
            border-radius: 9px;
        }}
        #key {{ color: {P['muted']}; font-size: 11px; min-width: 80px; }}
        #val {{ font-size: 12px; font-weight: 600; }}

        #sectionHdr {{
            color: {P['dim']};
            font-size: 10px;
            font-weight: 700;
            letter-spacing: 1.5px;
            text-transform: uppercase;
        }}
        #logBox {{
            background: {P['surface']};
            border: 1px solid {P['border']};
            border-radius: 8px;
            color: {P['muted']};
            font-size: 10px;
            padding: 5px 8px;
        }}

        QPushButton {{
            border-radius: 7px;
            font-size: 11px;
            font-weight: 600;
            border: 1px solid;
            padding: 0 10px;
        }}
        #btn_green  {{ background:#1a3326; color:{P['green']};  border-color:#2d5a40; }}
        #btn_green:hover  {{ background:#23472e; }}
        #btn_red    {{ background:#3b1219; color:{P['red']};    border-color:#6b2228; }}
        #btn_red:hover    {{ background:#4d1820; }}
        #btn_blue   {{ background:#1a2840; color:{P['blue']};   border-color:#2d4a6b; }}
        #btn_blue:hover   {{ background:#233555; }}
        #btn_purple {{ background:#261a40; color:{P['purple']}; border-color:#4a2d6b; }}
        #btn_purple:hover {{ background:#332255; }}
        #btn_orange {{ background:#3b2b12; color:{P['orange']}; border-color:#6b4a20; }}
        #btn_orange:hover {{ background:#4d3818; }}
        #btn_orange_on {{ background:{P['orange']}; color:#111; border-color:{P['orange']}; font-weight:800; }}
        #btn_teal   {{ background:#122830; color:#4ec9b0;       border-color:#206050; }}
        #btn_teal:hover   {{ background:#1a3a40; }}
        #btn_teal_on {{ background:#4ec9b0; color:#0d1117;      border-color:#4ec9b0; font-weight:800; }}
        #btn_dim    {{ background:{P['surface2']}; color:{P['muted']}; border-color:{P['border']}; }}
        #btn_dim:hover    {{ background:{P['border']}; color:{P['text']}; }}
        """)

    # ── state update slot ─────────────────────────────────────────────────────
    def on_state(self, state: TorState) -> None:
        color = state.mode_color()
        self._dot.setStyleSheet(f"color: {color};")
        self._mode.setText(state.mode_label())
        self._mode.setStyleSheet(f"color: {color}; font-size: 14px; font-weight: 700;")
        self._ts.setText(state.ts)

        self._v_exit.setText(state.exit_ip)
        self._v_real.setText(state.real_ip)
        self._v_country.setText(f"{state.flag()}  {state.country}")
        self._v_isp.setText(state.isp)
        self._v_latency.setText(f"{state.latency_ms} ms" if state.latency_ms else "—")

        route_labels = {
            "connected":    f"🟢  TOR  (exit {state.exit_ip})",
            "connecting":   "🟡  TOR  (building circuit)",
            "disconnected": "🔴  DIRECT — not protected",
            "leak":         "🔴  LEAK — real IP exposed",
            "init":         "⬜  Unknown",
        }
        self._v_route.setText(route_labels.get(state.mode, state.mode))

        self._push_log("INFO", f"{state.mode.upper():12s}  exit={state.exit_ip}"
                       + (f"  {state.latency_ms}ms" if state.latency_ms else "")
                       + (f"  [{state.country}]" if state.country != "—" else "")
                       + (f"  ⚠ LEAK" if state.leak else ""))

    # ── log ───────────────────────────────────────────────────────────────────
    def _push_log(self, level: str, msg: str) -> None:
        ts    = datetime.now().strftime("%H:%M:%S")
        entry = f"[{ts}] {level:4s}  {msg}"
        self._log_buf.append(entry)
        self._log.setPlainText("\n".join(self._log_buf))
        sb = self._log.verticalScrollBar()
        sb.setValue(sb.maximum())

    def log_event(self, level: str, msg: str) -> None:
        self._push_log(level, msg)

    # ── actions ───────────────────────────────────────────────────────────────
    def _act_start(self) -> None:
        self._push_log("INFO", "Starting tor service…")
        ok, out = TorControl.start()
        self._push_log("OK" if ok else "ERR", out or "—")
        if ok:
            QTimer.singleShot(1500, self.probe.probe_now)

    def _act_stop(self) -> None:
        self._push_log("INFO", "Stopping tor service…")
        ok, out = TorControl.stop()
        self._push_log("OK" if ok else "ERR", out or "—")
        if ok:
            QTimer.singleShot(1000, self.probe.probe_now)

    def _act_restart(self) -> None:
        self._push_log("INFO", "Restarting tor service…")
        ok, out = TorControl.restart()
        self._push_log("OK" if ok else "ERR", out or "—")
        if ok:
            QTimer.singleShot(2000, self.probe.probe_now)

    def _act_newid(self) -> None:
        self._push_log("INFO", "Requesting new identity…")
        ok, out = TorControl.new_identity()
        self._push_log("OK" if ok else "ERR", out)
        if ok:
            QTimer.singleShot(3000, self.probe.probe_now)

    def _act_ks(self) -> None:
        self._ks_on = not self._ks_on
        if self._ks_on:
            ok, out = TorControl.killswitch_on()
            self._b_ks.setText("🔓  Kill Switch: ON")
            self._b_ks.setObjectName("btn_orange_on")
        else:
            ok, out = TorControl.killswitch_off()
            self._b_ks.setText("🔒  Kill Switch")
            self._b_ks.setObjectName("btn_orange")
        self._b_ks.setStyleSheet("")
        self._style()
        self._push_log("OK" if ok else "ERR", out)

    def _act_tp(self) -> None:
        self._tp_on = not self._tp_on
        if self._tp_on:
            ok, out = TorControl.transparent_proxy_on()
            self._b_tp.setText("⬡  Transparent: ON")
            self._b_tp.setObjectName("btn_teal_on")
        else:
            ok, out = TorControl.transparent_proxy_off()
            self._b_tp.setText("⬡  Transparent")
            self._b_tp.setObjectName("btn_teal")
        self._b_tp.setStyleSheet("")
        self._style()
        self._push_log("OK" if ok else "ERR", out)

    def _act_probe(self) -> None:
        self._push_log("INFO", "Manual probe triggered…")
        self.probe.probe_now()

    # ── drag ─────────────────────────────────────────────────────────────────
    def _mp(self, ev) -> None:
        if ev.button() == Qt.MouseButton.LeftButton:
            self._drag_pos = ev.globalPosition().toPoint() - self.frameGeometry().topLeft()

    def _mm(self, ev) -> None:
        if self._drag_pos and ev.buttons() == Qt.MouseButton.LeftButton:
            self.move(ev.globalPosition().toPoint() - self._drag_pos)

    def _mr(self, _) -> None:
        self._drag_pos = None


# ══════════════════════════════════════════════════════════════════════════════
#  SystemTray
# ══════════════════════════════════════════════════════════════════════════════
class TrayIcon(QSystemTrayIcon):

    def __init__(self, dash: Dashboard) -> None:
        super().__init__()
        self._dash = dash
        self.setIcon(_make_icon("init"))
        self.setToolTip("Tor Control Center — initializing")
        self._build_menu()
        self.activated.connect(self._activated)

    def _build_menu(self) -> None:
        m = QMenu()
        m.setStyleSheet(f"""
            QMenu {{
                background: {P['surface']};
                border: 1px solid {P['border']};
                border-radius: 8px;
                padding: 4px;
                font-family: 'JetBrains Mono', monospace;
                font-size: 12px;
                color: {P['text']};
            }}
            QMenu::item {{ padding: 6px 18px; border-radius: 4px; }}
            QMenu::item:selected {{ background: {P['surface2']}; }}
            QMenu::separator {{ height: 1px; background: {P['border']}; margin: 3px 8px; }}
        """)

        def act(label: str, fn) -> QAction:
            a = QAction(label, m)
            a.triggered.connect(fn)
            return a

        m.addAction(act("🖥   Open Dashboard",   self._show))
        m.addSeparator()
        m.addAction(act("▶   Start Tor",         lambda: TorControl.start()))
        m.addAction(act("■   Stop Tor",          lambda: TorControl.stop()))
        m.addAction(act("↺   Restart Tor",       lambda: TorControl.restart()))
        m.addAction(act("⟳   New Identity",      lambda: TorControl.new_identity()))
        m.addSeparator()
        m.addAction(act("✕   Quit",              QApplication.quit))
        self.setContextMenu(m)

    def on_state(self, state: TorState) -> None:
        self.setIcon(_make_icon(state.mode))
        parts = [state.mode_label()]
        if state.exit_ip != "—":
            parts.append(state.exit_ip)
        if state.country != "—":
            parts.append(f"{state.flag()} {state.country}")
        if state.latency_ms:
            parts.append(f"{state.latency_ms}ms")
        if state.leak:
            parts.append("⚠ LEAK")
        self.setToolTip("🧅  " + "  ·  ".join(parts))

    def _activated(self, reason: QSystemTrayIcon.ActivationReason) -> None:
        if reason == QSystemTrayIcon.ActivationReason.Trigger:
            self._show()

    def _show(self) -> None:
        if self._dash.isVisible():
            self._dash.hide()
            return
        geo  = QApplication.primaryScreen().availableGeometry()
        w, h = self._dash.width(), self._dash.height()
        self._dash.move(geo.right() - w - 16, geo.bottom() - h - 52)
        self._dash.show()
        self._dash.raise_()
        self._dash.activateWindow()


# ══════════════════════════════════════════════════════════════════════════════
#  Entry
# ══════════════════════════════════════════════════════════════════════════════
def main() -> None:
    app = QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(False)
    app.setApplicationName("TorControlCenter")
    app.setApplicationVersion("2.0")

    if not QSystemTrayIcon.isSystemTrayAvailable():
        print("ERROR: No system tray found.")
        sys.exit(1)

    if not _HAS_REQUESTS:
        print("WARNING: requests not installed — network checks disabled.")

    probe = TorProbe()
    dash  = Dashboard(probe)
    tray  = TrayIcon(dash)

    probe.state_ready.connect(dash.on_state)
    probe.state_ready.connect(tray.on_state)
    probe.log_line.connect(dash.log_event)

    tray.show()
    probe.start()

    dash.log_event("INFO", "Tor Control Center v2 started")
    if not _HAS_REQUESTS:
        dash.log_event("WARN", "requests not found — install:  pip3 install requests[socks]")

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
