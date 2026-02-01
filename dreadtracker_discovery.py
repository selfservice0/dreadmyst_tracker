#!/usr/bin/env python3
"""
DreadMyst Opcode Discovery Tool

This version focuses on FINDING the correct opcodes by:
1. Filtering out high-frequency spam (opcodes that fire >10 times/sec)
2. Highlighting RARE events
3. Letting you mark timestamps when you do specific actions

WORKFLOW:
1. Start capture with this tool
2. Stand still for 10 seconds (let it learn what's spam)
3. Click "Mark Action" RIGHT BEFORE we kill a mob / pick up gold / etc
4. Check which opcodes fired right after your mark
"""

import os
import sys
import time
import json
import queue
import sqlite3
import subprocess
import threading
from dataclasses import dataclass
from collections import defaultdict, Counter, deque
from typing import Optional, Dict, Tuple, List

import tkinter as tk
from tkinter import ttk, filedialog, messagebox


REMOTE_PORT_DEFAULT = 16383


def u16le(b: bytes, off: int = 0) -> int:
    return int.from_bytes(b[off:off + 2], "little", signed=False)


def u32le(b: bytes, off: int = 0) -> int:
    return int.from_bytes(b[off:off + 4], "little", signed=False)


def hexdump(b: bytes, max_bytes: int = 32) -> str:
    if len(b) <= max_bytes:
        return b.hex()
    return b[:max_bytes].hex() + f"...({len(b)}B)"


# -----------------------------
# Streaming frame parser
# -----------------------------
class FrameStream:
    def __init__(self):
        self.buf = bytearray()

    def feed(self, chunk: bytes):
        if chunk:
            self.buf.extend(chunk)

    def pop_frames(self, max_frames: int = 1000) -> List[Tuple[int, bytes]]:
        frames = []
        n = 0
        while n < max_frames:
            if len(self.buf) < 4:
                break
            length = u32le(self.buf, 0)
            if length <= 0 or length > 10_000_000:
                del self.buf[0:1]
                continue
            if len(self.buf) < 4 + length:
                break
            payload = bytes(self.buf[4:4 + length])
            del self.buf[0:4 + length]

            if len(payload) < 2:
                continue
            opcode = u16le(payload, 0)
            body = payload[2:]
            frames.append((opcode, body))
            n += 1
        return frames


@dataclass
class TsharkPacket:
    ts: float
    src: str
    sport: int
    dst: str
    dport: int
    payload: bytes


class CaptureThread(threading.Thread):
    def __init__(self, q: "queue.Queue", stop_evt: threading.Event, tshark_path: str,
                 interface: str, remote_port: int):
        super().__init__(daemon=True)
        self.q = q
        self.stop_evt = stop_evt
        self.tshark_path = tshark_path
        self.interface = interface
        self.remote_port = remote_port
        self.proc: Optional[subprocess.Popen] = None

    def run(self):
        args = [
            self.tshark_path, "-l", "-n",
            "-i", str(self.interface),
            "-f", f"tcp port {self.remote_port}",
            "-T", "fields", "-E", "separator=\t", "-E", "occurrence=f",
            "-e", "frame.time_epoch", "-e", "ip.src", "-e", "tcp.srcport",
            "-e", "ip.dst", "-e", "tcp.dstport", "-e", "tcp.payload",
        ]

        try:
            self.proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                         text=True, bufsize=1)
        except Exception as e:
            self.q.put(("log", f"[!] Failed to start tshark: {e}"))
            return

        self.q.put(("log", f"[+] Capture started on interface {self.interface}"))

        while not self.stop_evt.is_set():
            if self.proc.poll() is not None:
                break
            line = self.proc.stdout.readline() if self.proc.stdout else ""
            if not line:
                time.sleep(0.01)
                continue
            line = line.strip()
            if not line:
                continue

            parts = line.split("\t")
            if len(parts) < 6:
                continue

            try:
                ts = float(parts[0]) if parts[0] else time.time()
                src, dst = parts[1], parts[3]
                sport = int(parts[2]) if parts[2] else 0
                dport = int(parts[4]) if parts[4] else 0
                payload_hex = parts[5] or ""
                payload = bytes.fromhex(payload_hex.replace(":", "")) if payload_hex else b""
            except Exception:
                continue

            if payload:
                self.q.put(("pkt", TsharkPacket(ts, src, sport, dst, dport, payload)))

        self.q.put(("log", "[*] Capture thread exiting."))

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()


class OpcodeTracker:
    """Tracks opcode frequency to identify spam vs rare events."""
    
    def __init__(self):
        self.streams: Dict[Tuple, FrameStream] = defaultdict(FrameStream)
        
        # Frequency tracking (sliding window)
        self.opcode_times: Dict[int, deque] = defaultdict(lambda: deque(maxlen=100))
        self.opcode_total: Counter = Counter()
        self.opcode_bodies: Dict[int, List[bytes]] = defaultdict(list)  # Sample bodies
        
        # Spam detection
        self.spam_opcodes: set = set()
        self.spam_threshold = 5.0  # More than 5/sec = spam
        
        # Action markers
        self.markers: List[Tuple[float, str]] = []
        
    def add_marker(self, label: str):
        self.markers.append((time.time(), label))
        
    def get_rate(self, opcode: int) -> float:
        """Get packets/second for this opcode over last 5 seconds."""
        times = self.opcode_times[opcode]
        if len(times) < 2:
            return 0.0
        now = time.time()
        recent = [t for t in times if now - t < 5.0]
        if len(recent) < 2:
            return 0.0
        return len(recent) / 5.0
    
    def is_spam(self, opcode: int) -> bool:
        return opcode in self.spam_opcodes or self.get_rate(opcode) > self.spam_threshold
    
    def handle_packet(self, pkt: TsharkPacket, remote_port: int) -> List[dict]:
        events = []
        
        # Only server->client
        if pkt.sport != remote_port:
            return events
            
        key = (pkt.src, pkt.sport, pkt.dst, pkt.dport)
        fs = self.streams[key]
        fs.feed(pkt.payload)
        
        for opcode, body in fs.pop_frames():
            now = time.time()
            self.opcode_times[opcode].append(now)
            self.opcode_total[opcode] += 1
            
            # Store sample bodies (max 5 per opcode)
            if len(self.opcode_bodies[opcode]) < 5:
                self.opcode_bodies[opcode].append(body[:64])
            
            # Update spam detection
            if self.get_rate(opcode) > self.spam_threshold:
                self.spam_opcodes.add(opcode)
            
            # Check if this is near a marker
            near_marker = None
            for marker_ts, marker_label in reversed(self.markers[-10:]):
                if 0 <= (now - marker_ts) <= 3.0:  # Within 3 sec after marker
                    near_marker = marker_label
                    break
            
            events.append({
                "ts": pkt.ts,
                "opcode": opcode,
                "body_len": len(body),
                "body_hex": hexdump(body, 32),
                "is_spam": self.is_spam(opcode),
                "rate": self.get_rate(opcode),
                "near_marker": near_marker,
                # Parse potential values for inspection
                "u32_0": u32le(body, 0) if len(body) >= 4 else None,
                "u32_4": u32le(body, 4) if len(body) >= 8 else None,
                "u32_8": u32le(body, 8) if len(body) >= 12 else None,
            })
        
        return events
    
    def get_summary(self) -> str:
        lines = [
            "=" * 70,
            "OPCODE SUMMARY - Sorted by frequency (lowest first = most interesting)",
            "=" * 70,
            f"{'OP':>4} {'Total':>8} {'Rate/s':>7} {'Len':>6} {'Spam?':>6}  Sample Hex",
            "-" * 70
        ]
        
        # Sort by total count ascending (rare opcodes first)
        for opcode, count in sorted(self.opcode_total.items(), key=lambda x: x[1]):
            rate = self.get_rate(opcode)
            is_spam = "SPAM" if opcode in self.spam_opcodes else ""
            
            # Get common body length
            bodies = self.opcode_bodies.get(opcode, [])
            lens = [len(b) for b in bodies]
            len_str = str(lens[0]) if lens else "?"
            
            # Sample hex
            sample = bodies[0].hex()[:24] if bodies else ""
            
            lines.append(f"{opcode:4d} {count:8d} {rate:7.1f} {len_str:>6} {is_spam:>6}  {sample}")
        
        return "\n".join(lines)


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("DreadMyst Opcode Discovery")
        self.geometry("1000x750")

        self.q: queue.Queue = queue.Queue()
        self.stop_evt = threading.Event()
        self.capture_thread: Optional[CaptureThread] = None
        self.tracker = OpcodeTracker()

        self.tshark_path = tk.StringVar(value=self._default_tshark())
        self.interface_var = tk.StringVar(value="5")
        self.port_var = tk.StringVar(value=str(REMOTE_PORT_DEFAULT))
        self.hide_spam_var = tk.BooleanVar(value=True)
        self.marker_label_var = tk.StringVar(value="KILL")

        self._build_ui()
        self.after(100, self._poll)

    def _default_tshark(self) -> str:
        p = r"C:\Program Files\Wireshark\tshark.exe"
        return p if os.path.exists(p) else "tshark"

    def _build_ui(self):
        # Top controls
        top = ttk.Frame(self)
        top.pack(fill="x", padx=10, pady=5)

        ttk.Label(top, text="tshark:").grid(row=0, column=0, sticky="w")
        ttk.Entry(top, textvariable=self.tshark_path, width=45).grid(row=0, column=1, padx=5)
        ttk.Button(top, text="Browse", command=self._browse).grid(row=0, column=2)
        ttk.Button(top, text="Interfaces", command=self._list_ifaces).grid(row=0, column=3, padx=5)

        ttk.Label(top, text="Iface#:").grid(row=1, column=0, sticky="w")
        ttk.Entry(top, textvariable=self.interface_var, width=8).grid(row=1, column=1, sticky="w", padx=5)
        ttk.Label(top, text="Port:").grid(row=1, column=2, sticky="e")
        ttk.Entry(top, textvariable=self.port_var, width=8).grid(row=1, column=3, sticky="w")

        # Control buttons
        ctrl = ttk.Frame(self)
        ctrl.pack(fill="x", padx=10, pady=5)

        self.start_btn = ttk.Button(ctrl, text="Start Capture", command=self._start)
        self.stop_btn = ttk.Button(ctrl, text="Stop", command=self._stop, state="disabled")
        self.start_btn.pack(side="left", padx=5)
        self.stop_btn.pack(side="left", padx=5)

        ttk.Separator(ctrl, orient="vertical").pack(side="left", fill="y", padx=10)

        ttk.Label(ctrl, text="Mark:").pack(side="left")
        ttk.Entry(ctrl, textvariable=self.marker_label_var, width=10).pack(side="left", padx=5)
        ttk.Button(ctrl, text="⚡ MARK ACTION", command=self._mark_action).pack(side="left", padx=5)

        ttk.Separator(ctrl, orient="vertical").pack(side="left", fill="y", padx=10)

        ttk.Checkbutton(ctrl, text="Hide Spam", variable=self.hide_spam_var).pack(side="left", padx=5)
        ttk.Button(ctrl, text="Show Summary", command=self._show_summary).pack(side="left", padx=5)
        ttk.Button(ctrl, text="Clear", command=self._clear).pack(side="left", padx=5)

        # Instructions
        inst = ttk.Label(self, text="⚡ Click 'MARK ACTION' right BEFORE you kill/loot, then look for opcodes that fire after your mark",
                        font=("Segoe UI", 9, "italic"), foreground="blue")
        inst.pack(pady=5)

        # Event list
        cols = ("time", "marker", "op", "len", "rate", "values", "hex")
        self.tree = ttk.Treeview(self, columns=cols, show="headings", height=20)
        self.tree.heading("time", text="Time")
        self.tree.heading("marker", text="Marker")
        self.tree.heading("op", text="Opcode")
        self.tree.heading("len", text="Len")
        self.tree.heading("rate", text="Rate/s")
        self.tree.heading("values", text="u32[0] / u32[4] / u32[8]")
        self.tree.heading("hex", text="Body Hex")

        self.tree.column("time", width=85)
        self.tree.column("marker", width=60)
        self.tree.column("op", width=55)
        self.tree.column("len", width=45)
        self.tree.column("rate", width=50)
        self.tree.column("values", width=180)
        self.tree.column("hex", width=400)

        scroll = ttk.Scrollbar(self, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side="left", fill="both", expand=True, padx=(10, 0), pady=5)
        scroll.pack(side="left", fill="y", pady=5)

        # Tag for highlighted rows
        self.tree.tag_configure("marked", background="#90EE90")
        self.tree.tag_configure("rare", background="#FFFACD")

        # Log
        log_frame = ttk.LabelFrame(self, text="Log")
        log_frame.pack(fill="x", padx=10, pady=5)
        self.log_text = tk.Text(log_frame, height=4, wrap="word")
        self.log_text.pack(fill="x")

    def _browse(self):
        p = filedialog.askopenfilename(filetypes=[("Executable", "*.exe"), ("All", "*.*")])
        if p:
            self.tshark_path.set(p)

    def _list_ifaces(self):
        try:
            out = subprocess.check_output([self.tshark_path.get(), "-D"], text=True, stderr=subprocess.STDOUT)
            self._log(out.strip())
        except Exception as e:
            self._log(f"Error: {e}")

    def _start(self):
        iface = self.interface_var.get().strip()
        try:
            port = int(self.port_var.get())
        except ValueError:
            messagebox.showerror("Error", "Invalid port")
            return

        self.stop_evt.clear()
        self.capture_thread = CaptureThread(self.q, self.stop_evt, self.tshark_path.get(), iface, port)
        self.capture_thread.start()
        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self._log("[*] Started. Stand idle for 10s to learn spam patterns, then use MARK ACTION before kills/loots.")

    def _stop(self):
        self.stop_evt.set()
        if self.capture_thread:
            self.capture_thread.stop()
        self.start_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        self._log("[*] Stopped")

    def _mark_action(self):
        label = self.marker_label_var.get() or "ACTION"
        self.tracker.add_marker(label)
        self._log(f"[MARKER] {label} at {time.strftime('%H:%M:%S')}")

    def _show_summary(self):
        win = tk.Toplevel(self)
        win.title("Opcode Summary")
        win.geometry("750x500")
        txt = tk.Text(win, font=("Consolas", 10))
        txt.pack(fill="both", expand=True)
        txt.insert("1.0", self.tracker.get_summary())

    def _clear(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.tracker = OpcodeTracker()
        self._log("[*] Cleared")

    def _poll(self):
        try:
            while True:
                kind, data = self.q.get_nowait()
                if kind == "log":
                    self._log(data)
                elif kind == "pkt":
                    self._handle_pkt(data)
        except queue.Empty:
            pass
        self.after(50, self._poll)

    def _handle_pkt(self, pkt: TsharkPacket):
        try:
            port = int(self.port_var.get())
        except ValueError:
            port = REMOTE_PORT_DEFAULT

        events = self.tracker.handle_packet(pkt, port)
        
        for ev in events:
            # Skip spam if hidden
            if self.hide_spam_var.get() and ev["is_spam"]:
                continue

            t_str = time.strftime("%H:%M:%S", time.localtime(ev["ts"]))
            marker = ev.get("near_marker") or ""
            values = f"{ev['u32_0']} / {ev['u32_4']} / {ev['u32_8']}"

            # Determine tag
            tags = ()
            if marker:
                tags = ("marked",)
            elif ev["rate"] < 1.0 and self.tracker.opcode_total[ev["opcode"]] < 50:
                tags = ("rare",)

            self.tree.insert("", 0, values=(
                t_str, marker, ev["opcode"], ev["body_len"], 
                f"{ev['rate']:.1f}", values, ev["body_hex"]
            ), tags=tags)

        # Trim tree
        children = self.tree.get_children()
        if len(children) > 500:
            for iid in children[500:]:
                self.tree.delete(iid)

    def _log(self, msg: str):
        self.log_text.insert(tk.END, msg + "\n")
        self.log_text.see(tk.END)


if __name__ == "__main__":

    App().mainloop()
