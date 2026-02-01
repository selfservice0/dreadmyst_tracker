#!/usr/bin/env python3
"""
DreadMyst Tracker v6 

Discovered through packet analysis:
- Opcode 104 (len 16) = NotifyItemAdd: [u32 item_id][u32 variant][u32 amount][u32 extra]
- Opcode 119 (len 4)  = SpentGold: [u32 amount]
- Opcode 86  (len varies) = OpenLootWindow (contains gold + item list)
- Opcode 99  = CombatMsg (damage/healing)

Gold when looting: Need to parse from OpenLootWindow packet or find gold item ID
"""

import os
import time
import queue
import sqlite3
import subprocess
import threading
from dataclasses import dataclass
from collections import defaultdict, Counter
from typing import Optional, Dict, Tuple, List

import tkinter as tk
from tkinter import ttk, filedialog, messagebox


REMOTE_PORT_DEFAULT = 16383

# CONFIRMED OPCODES
OP_ITEM_ADD = 104       # NotifyItemAdd - 16 bytes
OP_GOLD_SPENT = 119     # SpentGold - 4 bytes
OP_LOOT_WINDOW = 86     # OpenLootWindow - variable
OP_COMBAT_MSG = 92      # CombatMsg - damage/healing (len 68-85)
OP_KILL_EXP = 108       # Kill notification - len 12, exp at u32[4]


def u16le(b: bytes, off: int = 0) -> int:
    return int.from_bytes(b[off:off + 2], "little", signed=False)

def u32le(b: bytes, off: int = 0) -> int:
    return int.from_bytes(b[off:off + 4], "little", signed=False)


class ItemDb:
    def __init__(self, path: str):
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self.cache: Dict[int, str] = {}
        
        cur = self.conn.execute("PRAGMA table_info(item_template)")
        cols = [r["name"] for r in cur.fetchall()]
        self.key_col = next((c for c in ["entry", "id"] if c in cols), cols[0])

    def close(self):
        self.conn.close()

    def get_name(self, item_id: int) -> str:
        if item_id in self.cache:
            return self.cache[item_id]
        
        cur = self.conn.execute(
            f"SELECT name FROM item_template WHERE {self.key_col} = ?", (item_id,)
        )
        row = cur.fetchone()
        name = row["name"] if row else f"Unknown Item ({item_id})"
        self.cache[item_id] = name
        return name


class FrameStream:
    def __init__(self):
        self.buf = bytearray()

    def feed(self, chunk: bytes):
        self.buf.extend(chunk)

    def pop_frames(self) -> List[Tuple[int, bytes]]:
        frames = []
        while len(self.buf) >= 4:
            length = u32le(self.buf, 0)
            if length <= 0 or length > 10_000_000:
                del self.buf[0:1]
                continue
            if len(self.buf) < 4 + length:
                break
            payload = bytes(self.buf[4:4 + length])
            del self.buf[0:4 + length]
            if len(payload) >= 2:
                frames.append((u16le(payload, 0), payload[2:]))
        return frames


@dataclass
class Packet:
    ts: float
    sport: int
    dport: int
    payload: bytes


class CaptureThread(threading.Thread):
    def __init__(self, q: queue.Queue, stop_evt: threading.Event,
                 tshark: str, iface: str, port: int):
        super().__init__(daemon=True)
        self.q = q
        self.stop_evt = stop_evt
        self.tshark = tshark
        self.iface = iface
        self.port = port
        self.proc = None

    def run(self):
        args = [
            self.tshark, "-l", "-n", "-i", str(self.iface),
            "-f", f"tcp port {self.port}",
            "-T", "fields", "-E", "separator=\t", "-E", "occurrence=f",
            "-e", "frame.time_epoch", "-e", "tcp.srcport", 
            "-e", "tcp.dstport", "-e", "tcp.payload",
        ]
        
        try:
            self.proc = subprocess.Popen(args, stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE, text=True, bufsize=1)
        except Exception as e:
            self.q.put(("log", f"[!] tshark error: {e}"))
            return

        self.q.put(("log", "[+] Capture started"))

        while not self.stop_evt.is_set():
            if self.proc.poll() is not None:
                break
            line = self.proc.stdout.readline()
            if not line:
                time.sleep(0.01)
                continue
            
            parts = line.strip().split("\t")
            if len(parts) < 4:
                continue
            
            try:
                ts = float(parts[0]) if parts[0] else time.time()
                sport = int(parts[1]) if parts[1] else 0
                dport = int(parts[2]) if parts[2] else 0
                payload = bytes.fromhex(parts[3].replace(":", "")) if parts[3] else b""
                if payload:
                    self.q.put(("pkt", Packet(ts, sport, dport, payload)))
            except:
                continue

        self.q.put(("log", "[*] Capture stopped"))

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()


class Tracker:
    def __init__(self):
        self.streams: Dict[Tuple[int, int], FrameStream] = defaultdict(FrameStream)
        self.itemdb: Optional[ItemDb] = None
        
        # Stats
        self.item_totals = Counter()
        self.gold_looted = 0
        self.gold_spent = 0
        self.kills = 0
        self.loots = 0
        
        # Combat tracking for kill inference
        self.last_combat_ts: Optional[float] = None
        self.last_kill_ts: Optional[float] = None  # Rate limit kills
        self.last_exp: int = 0  # Track exp for delta calculation, likely wrong
        
        # Debug
        self.debug = False
        self.debug_fn = None

    def set_itemdb(self, db: Optional[ItemDb]):
        if self.itemdb:
            self.itemdb.close()
        self.itemdb = db

    def set_debug(self, enabled: bool, fn=None):
        self.debug = enabled
        self.debug_fn = fn

    def _dbg(self, msg: str):
        if self.debug and self.debug_fn:
            self.debug_fn(msg)

    def handle_packet(self, pkt: Packet, port: int) -> List[dict]:
        if pkt.sport != port:
            return []

        events = []
        key = (pkt.sport, pkt.dport)
        fs = self.streams[key]
        fs.feed(pkt.payload)

        for opcode, body in fs.pop_frames():
            
            # ===== ITEM RECEIVED (opcode 104) =====
            # Structure: [u16 ?][u16 item_id][8 bytes padding][u32 amount at offset 12]
            if opcode == OP_ITEM_ADD and len(body) >= 8:
                self._dbg(f"[ITEM RAW] len={len(body)} hex={body.hex()}")
                
                # Item ID is u16 at offset 2
                item_id = u16le(body, 2)
                
                # Debug: show all u32 values at each offset
                debug_vals = []
                for off in range(0, min(len(body) - 3, 20), 4):
                    val = u32le(body, off)
                    debug_vals.append(f"@{off}={val}")
                self._dbg(f"[ITEM VALS] {' '.join(debug_vals)}")
                
                # Amount extraction - values appear to be at odd byte offsets
                # Try multiple positions to find the actual amount
                amount = 1
                
                # Method 1: Try reading from byte offset 11 (odd offset)
                if len(body) >= 15 and amount == 1:
                    val = u32le(body, 11)
                    if 1 <= val <= 10_000_000:
                        amount = val
                        self._dbg(f"[ITEM] amount from offset 11: {amount}")
                
                # Method 2: Try byte offset 13
                if len(body) >= 17 and amount == 1:
                    val = u32le(body, 13)
                    if 1 <= val <= 10_000_000:
                        amount = val
                        self._dbg(f"[ITEM] amount from offset 13: {amount}")
                
                # Method 3: Read u32 from offset 12
                if len(body) >= 16 and amount == 1:
                    val = u32le(body, 12)
                    if 1 <= val <= 10_000_000:
                        amount = val
                        self._dbg(f"[ITEM] amount from offset 12: {amount}")
                
                # Method 4: If value is suspiciously high (256x), divide by 256
                if amount >= 256 and amount % 256 == 0:
                    corrected = amount // 256
                    if corrected >= 1:
                        self._dbg(f"[ITEM] correcting {amount} -> {corrected} (div 256)")
                        amount = corrected
                
                self._dbg(f"[ITEM] id={item_id} final_amt={amount}")
                
                # Get item name
                name = self.itemdb.get_name(item_id) if self.itemdb else f"Item {item_id}"
                
                self._dbg(f"[ITEM] id={item_id} amt={amount} -> {name}")
                
                # Check if this is gold (by name pattern)
                if "gold" in name.lower():
                    self.gold_looted += amount
                    events.append({
                        "type": "gold",
                        "ts": pkt.ts,
                        "amount": amount,
                        "total": self.gold_looted
                    })
                else:
                    self.item_totals[name] += amount
                    events.append({
                        "type": "item",
                        "ts": pkt.ts,
                        "item_id": item_id,
                        "name": name,
                        "count": amount
                    })
                
                # Kill detection now handled by OP_KILL_EXP (opcode 1)

            # ===== GOLD SPENT (opcode 119, 4 bytes) =====
            elif opcode == OP_GOLD_SPENT and len(body) == 4:
                amount = u32le(body, 0)
                self.gold_spent += amount
                
                self._dbg(f"[GOLD SPENT] {amount}")
                
                events.append({
                    "type": "gold_spent",
                    "ts": pkt.ts,
                    "amount": amount,
                    "total_spent": self.gold_spent
                })

            # ===== LOOT WINDOW (opcode 86) =====
            elif opcode == OP_LOOT_WINDOW and len(body) > 10:
                self.loots += 1
                
                self._dbg(f"[LOOT] len={len(body)} hex={body[:32].hex()}")
                
                # Try to extract gold from loot window
                # Structure likely: [guid 8 bytes][gold 4 bytes][item count][items...]
                if len(body) >= 12:
                    # Try gold at offset 8 (after guid)
                    potential_gold = u32le(body, 8)
                    if 1 <= potential_gold <= 10_000_000:
                        self.gold_looted += potential_gold
                        events.append({
                            "type": "gold",
                            "ts": pkt.ts,
                            "amount": potential_gold,
                            "total": self.gold_looted,
                            "source": "loot_window"
                        })
                        self._dbg(f"  -> gold from loot window: {potential_gold}")
                
                # TODO: Need to find proper kill opcode via discovery

            # ===== KILL DETECTION (opcode 1, len 8) =====
            # u32[4] is TOTAL exp. We look for significant jumps (deltas) to detect kills.
            elif opcode == 1 and len(body) == 8:
                current_exp = u32le(body, 4)
                
                # If we have a previous exp value to compare against
                if self.last_exp > 0:
                    delta = current_exp - self.last_exp
                    
                    # Filter out small passive gains (likely < 10)
                    # A mob kill seems to be around ~94 exp based on logs
                    if delta > 10:
                        self.kills += 1
                        self._dbg(f"[KILL] #{self.kills} exp_delta={delta} (total: {current_exp})")
                        events.append({
                            "type": "kill",
                            "ts": pkt.ts,
                            "total": self.kills,
                            "exp": delta
                        })
                    elif delta > 0:
                        self._dbg(f"[EXP] Passive gain: +{delta} (total: {current_exp})")
                
                # Update last known exp
                self.last_exp = current_exp

            # ===== DAMAGE (opcode 108, len 12) =====
            # u32[4] appears to be damage value (e.g. 6000, 3000, 15000)
            elif opcode == 108 and len(body) == 12:
                dmg = u32le(body, 4)
                # Some values might be huge/flags, filter reasonable range if needed
                # Assuming raw value, maybe decimals?
                self._dbg(f"[DAMAGE] val={dmg}")
                events.append({
                    "type": "damage",
                    "ts": pkt.ts,
                    "amount": dmg
                })

            # ===== COMBAT (opcode 92) =====
            elif opcode == OP_COMBAT_MSG:
                self.last_combat_ts = pkt.ts

        return events

    def reset(self):
        self.item_totals.clear()
        self.gold_looted = 0
        self.gold_spent = 0
        self.kills = 0
        self.loots = 0
        self.last_combat_ts = None
        self.last_kill_ts = None
        self.last_exp = 0


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("DreadMyst Tracker v6")
        self.geometry("900x650")

        self.q = queue.Queue()
        self.stop_evt = threading.Event()
        self.capture_thread = None
        self.tracker = Tracker()

        self.tshark_var = tk.StringVar(value=self._find_tshark())
        self.iface_var = tk.StringVar(value="5")
        self.port_var = tk.StringVar(value=str(REMOTE_PORT_DEFAULT))
        self.db_var = tk.StringVar(value="")
        self.debug_var = tk.BooleanVar(value=True)

        self._build_ui()
        self.after(100, self._poll)

    def _find_tshark(self) -> str:
        p = r"C:\Program Files\Wireshark\tshark.exe"
        return p if os.path.exists(p) else "tshark"

    def _build_ui(self):
        # Config frame
        cfg = ttk.LabelFrame(self, text="Config")
        cfg.pack(fill="x", padx=10, pady=5)

        ttk.Label(cfg, text="tshark:").grid(row=0, column=0, sticky="w", padx=5)
        ttk.Entry(cfg, textvariable=self.tshark_var, width=50).grid(row=0, column=1, padx=5)
        ttk.Button(cfg, text="...", width=3, command=self._browse_tshark).grid(row=0, column=2)
        ttk.Button(cfg, text="List", command=self._list_ifaces).grid(row=0, column=3, padx=5)

        ttk.Label(cfg, text="Iface:").grid(row=1, column=0, sticky="w", padx=5)
        ttk.Entry(cfg, textvariable=self.iface_var, width=8).grid(row=1, column=1, sticky="w", padx=5)
        ttk.Label(cfg, text="Port:").grid(row=1, column=2, sticky="e")
        ttk.Entry(cfg, textvariable=self.port_var, width=8).grid(row=1, column=3, sticky="w")

        ttk.Label(cfg, text="game.db:").grid(row=2, column=0, sticky="w", padx=5)
        ttk.Entry(cfg, textvariable=self.db_var, width=50).grid(row=2, column=1, padx=5)
        ttk.Button(cfg, text="...", width=3, command=self._browse_db).grid(row=2, column=2)

        # Controls
        ctrl = ttk.Frame(self)
        ctrl.pack(fill="x", padx=10, pady=5)

        self.start_btn = ttk.Button(ctrl, text="▶ Start", command=self._start)
        self.stop_btn = ttk.Button(ctrl, text="⏹ Stop", command=self._stop, state="disabled")
        
        self.start_btn.pack(side="left", padx=5)
        self.stop_btn.pack(side="left", padx=5)
        ttk.Button(ctrl, text="↺ Reset", command=self._reset).pack(side="left", padx=15)
        ttk.Checkbutton(ctrl, text="Debug", variable=self.debug_var,
                       command=self._toggle_debug).pack(side="left", padx=10)

        # Stats
        stats = ttk.LabelFrame(self, text="Session")
        stats.pack(fill="x", padx=10, pady=5)

        self.stats_var = tk.StringVar(value="💰 Gold: +0 / -0 (net 0)  |  📦 Items: 0  |  💀 Kills: 0")
        ttk.Label(stats, textvariable=self.stats_var, font=("Segoe UI", 13, "bold"),
                 foreground="#228B22").pack(pady=8)

        # Tabs
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=10, pady=5)

        # Events
        ev_frame = ttk.Frame(nb)
        nb.add(ev_frame, text="Events")

        cols = ("time", "type", "detail")
        self.tree = ttk.Treeview(ev_frame, columns=cols, show="headings", height=10)
        self.tree.heading("time", text="Time")
        self.tree.heading("type", text="Type")
        self.tree.heading("detail", text="Detail")
        self.tree.column("time", width=80)
        self.tree.column("type", width=80)
        self.tree.column("detail", width=500)
        self.tree.pack(fill="both", expand=True)

        self.tree.tag_configure("gold", foreground="#FFD700")
        self.tree.tag_configure("spent", foreground="#FF6347")
        self.tree.tag_configure("item", foreground="#00CED1")
        self.tree.tag_configure("kill", foreground="#FF4500")

        # Loot
        loot_frame = ttk.Frame(nb)
        nb.add(loot_frame, text="Loot Totals")
        self.loot_text = tk.Text(loot_frame, font=("Consolas", 11))
        self.loot_text.pack(fill="both", expand=True)

        # Debug
        dbg_frame = ttk.Frame(nb)
        nb.add(dbg_frame, text="Debug")
        self.dbg_text = tk.Text(dbg_frame, font=("Consolas", 9), wrap="none")
        self.dbg_text.pack(fill="both", expand=True)

        # Log
        log_frame = ttk.LabelFrame(self, text="Log")
        log_frame.pack(fill="x", padx=10, pady=5)
        self.log_text = tk.Text(log_frame, height=3)
        self.log_text.pack(fill="x")

    def _toggle_debug(self):
        self.tracker.set_debug(self.debug_var.get(), self._dbg)

    def _dbg(self, msg: str):
        self.dbg_text.insert(tk.END, msg + "\n")
        self.dbg_text.see(tk.END)
        if int(self.dbg_text.index('end-1c').split('.')[0]) > 1500:
            self.dbg_text.delete('1.0', '500.0')

    def _browse_tshark(self):
        p = filedialog.askopenfilename(filetypes=[("Executable", "*.exe")])
        if p:
            self.tshark_var.set(p)

    def _browse_db(self):
        p = filedialog.askopenfilename(filetypes=[("SQLite", "*.db")])
        if p:
            self.db_var.set(p)
            try:
                self.tracker.set_itemdb(ItemDb(p))
                self._log(f"[+] DB: {p}")
            except Exception as e:
                self._log(f"[!] DB error: {e}")

    def _list_ifaces(self):
        try:
            out = subprocess.check_output([self.tshark_var.get(), "-D"],
                                         text=True, stderr=subprocess.STDOUT)
            self._log(out.strip())
        except Exception as e:
            self._log(f"[!] {e}")

    def _start(self):
        iface = self.iface_var.get().strip()
        try:
            port = int(self.port_var.get())
        except:
            messagebox.showerror("Error", "Invalid port")
            return

        db = self.db_var.get().strip()
        if db and not self.tracker.itemdb:
            try:
                self.tracker.set_itemdb(ItemDb(db))
            except:
                pass

        self._toggle_debug()
        self.stop_evt.clear()
        self.capture_thread = CaptureThread(self.q, self.stop_evt,
                                            self.tshark_var.get(), iface, port)
        self.capture_thread.start()
        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")

    def _stop(self):
        self.stop_evt.set()
        if self.capture_thread:
            self.capture_thread.stop()
        self.start_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")

    def _reset(self):
        self.tracker.reset()
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.loot_text.delete("1.0", tk.END)
        self.dbg_text.delete("1.0", tk.END)
        self._refresh_stats()
        self._log("[*] Reset")

    def _poll(self):
        try:
            while True:
                kind, data = self.q.get_nowait()
                if kind == "log":
                    self._log(data)
                elif kind == "pkt":
                    self._handle(data)
        except queue.Empty:
            pass
        self.after(100, self._poll)

    def _handle(self, pkt: Packet):
        try:
            port = int(self.port_var.get())
        except:
            port = REMOTE_PORT_DEFAULT

        events = self.tracker.handle_packet(pkt, port)
        for ev in events:
            self._render(ev)

        if events:
            self._refresh_stats()
            self._refresh_loot()

    def _render(self, ev: dict):
        ts = time.strftime("%H:%M:%S", time.localtime(ev.get("ts", time.time())))
        etype = ev.get("type", "?")

        if etype == "gold":
            src = f" ({ev['source']})" if ev.get('source') else ""
            detail = f"+{ev['amount']:,} gold{src}"
            tag = "gold"
        elif etype == "gold_spent":
            detail = f"-{ev['amount']:,} gold"
            tag = "spent"
        elif etype == "item":
            detail = f"{ev['name']} x{ev['count']}"
            tag = "item"
        elif etype == "kill":
            detail = f"Kill #{ev['total']}"
            tag = "kill"
        else:
            return

        self.tree.insert("", 0, values=(ts, etype, detail), tags=(tag,))
        
        children = self.tree.get_children()
        if len(children) > 150:
            for iid in children[150:]:
                self.tree.delete(iid)

    def _refresh_stats(self):
        t = self.tracker
        net = t.gold_looted - t.gold_spent
        items = sum(t.item_totals.values())
        self.stats_var.set(
            f"💰 Gold: +{t.gold_looted:,} / -{t.gold_spent:,} (net {net:,})  |  "
            f"📦 Items: {items}  |  💀 Kills: {t.kills}"
        )

    def _refresh_loot(self):
        t = self.tracker
        self.loot_text.delete("1.0", tk.END)
        self.loot_text.insert(tk.END, f"=== GOLD ===\n")
        self.loot_text.insert(tk.END, f"  Looted: +{t.gold_looted:,}\n")
        self.loot_text.insert(tk.END, f"  Spent:  -{t.gold_spent:,}\n")
        self.loot_text.insert(tk.END, f"  Net:     {t.gold_looted - t.gold_spent:,}\n\n")
        self.loot_text.insert(tk.END, f"=== ITEMS ({sum(t.item_totals.values())}) ===\n")
        for name, cnt in t.item_totals.most_common():
            self.loot_text.insert(tk.END, f"  {name}: {cnt}\n")

    def _log(self, msg: str):
        self.log_text.insert(tk.END, msg + "\n")
        self.log_text.see(tk.END)


if __name__ == "__main__":
    App().mainloop()