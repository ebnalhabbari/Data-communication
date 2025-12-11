# receiver.py  - Modern GUI Receiver (with Clear/Reset)

import socket
import threading
import tkinter as tk
from tkinter import ttk

LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 5001  # must match server's forward port

# ========== Error Detection Helpers (same as sender) ==========

def to_bytes(text: str) -> bytes:
    return text.encode("utf-8")


def parity_bit(data: bytes, mode: str = "even") -> str:
    ones = sum(bin(b).count("1") for b in data)
    if mode.lower() == "even":
        return "1" if ones % 2 else "0"
    return "0" if ones % 2 else "1"


def parity_2d(data: bytes, rows: int = 8, cols: int = 8) -> str:
    bits = "".join(f"{b:08b}" for b in data)
    block = rows * cols
    if len(bits) % block:
        bits += "0" * (block - len(bits) % block)
    out = []
    for start in range(0, len(bits), block):
        blk = bits[start:start + block]
        for r in range(rows):
            row_bits = blk[r * cols:(r + 1) * cols]
            out.append("1" if row_bits.count("1") % 2 else "0")
        for c in range(cols):
            col_bits = "".join(blk[r * cols + c] for r in range(rows))
            out.append("1" if col_bits.count("1") % 2 else "0")
    return "".join(out)


def crc16_ccitt(data: bytes) -> str:
    poly, crc = 0x1021, 0xFFFF
    for b in data:
        crc ^= (b << 8)
        for _ in range(8):
            crc = ((crc << 1) ^ poly) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return f"{crc:04X}"


def internet_checksum(data: bytes) -> str:
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i + 1]
        s = (s & 0xFFFF) + (s >> 16)
    return f"{(~s & 0xFFFF):04X}"


def hamming_12_8_parity_bits_for_byte(b: int) -> str:
    d = [(b >> (7 - i)) & 1 for i in range(8)]
    bits = [0] * 13
    bits[3], bits[5], bits[6], bits[7] = d[0:4]
    bits[9], bits[10], bits[11], bits[12] = d[4:8]
    p1 = p2 = p4 = p8 = 0
    for i in range(1, 13):
        if i & 1:
            p1 ^= bits[i]
        if i & 2:
            p2 ^= bits[i]
        if i & 4:
            p4 ^= bits[i]
        if i & 8:
            p8 ^= bits[i]
    return f"{p1}{p2}{p4}{p8}"


def hamming_control(data: bytes) -> str:
    return "".join(hamming_12_8_parity_bits_for_byte(b) for b in data)


METHOD_FUNCS = {
    "PARITY": lambda d: parity_bit(d, "even"),
    "PARITY2D": parity_2d,
    "CRC16": crc16_ccitt,
    "HAMMING": hamming_control,
    "CHECKSUM": internet_checksum,
}


def generate_control(msg: str, method: str) -> str:
    data = to_bytes(msg)
    func = METHOD_FUNCS.get(method.upper())
    if not func:
        raise ValueError(f"Unknown method: {method}")
    return func(data)


# ========== GUI + Receiver Logic ==========

class ReceiverApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Receiver - Data Communication")
        self.root.geometry("680x450")
        self.root.configure(bg="#050816")

        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        style.configure(
            "TLabel",
            background="#050816",
            foreground="#e5e7eb",
            font=("Segoe UI", 10),
        )
        style.configure(
            "Title.TLabel",
            font=("Segoe UI", 14, "bold"),
            foreground="#a855f7",
            background="#050816",
        )
        style.configure(
            "Secondary.TButton",
            font=("Segoe UI", 9),
            padding=4,
            relief="flat",
            background="#1f2937",
            foreground="#e5e7eb",
        )
        style.map(
            "Secondary.TButton",
            background=[("active", "#374151"), ("pressed", "#374151")],
        )

        header = ttk.Label(
            root,
            text="Receiver  •  Error Detection Checker",
            style="Title.TLabel",
            anchor="center",
        )
        header.pack(fill="x", pady=(10, 4))

        card = tk.Frame(root, bg="#0b1120", highlightthickness=1, highlightbackground="#1f2937")
        card.pack(fill="both", expand=True, padx=14, pady=10)

        # status + counters + clear
        self.status_label = ttk.Label(card, text="Waiting for packets...", foreground="#e5e7eb")
        self.status_label.grid(row=0, column=0, sticky="w", padx=10, pady=(10, 4))

        self.counter_label = ttk.Label(card, text="Correct: 0   |   Corrupted: 0")
        self.counter_label.grid(row=0, column=1, sticky="e", padx=10, pady=(10, 4))

        clear_btn = ttk.Button(card, text="Clear", style="Secondary.TButton", command=self.clear_reset)
        clear_btn.grid(row=0, column=2, sticky="e", padx=10, pady=(10, 4))

        # log
        log_frame = tk.Frame(card, bg="#0b1120")
        log_frame.grid(row=1, column=0, columnspan=3, sticky="nsew", padx=10, pady=(0, 10))

        self.log = tk.Text(
            log_frame,
            bg="#020617",
            fg="#e5e7eb",
            font=("Consolas", 9),
            relief="flat",
            wrap="word",
        )
        scroll = ttk.Scrollbar(log_frame, orient="vertical", command=self.log.yview)
        self.log.configure(yscrollcommand=scroll.set)
        self.log.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

        card.rowconfigure(1, weight=1)
        card.columnconfigure(0, weight=1)
        card.columnconfigure(1, weight=0)
        card.columnconfigure(2, weight=0)

        self.correct_count = 0
        self.corrupted_count = 0

        # start listening thread
        t = threading.Thread(target=self.listen_loop, daemon=True)
        t.start()

    def log_line(self, text: str):
        self.log.insert("end", text + "\n")
        self.log.see("end")

    def update_status(self, status: str, ok: bool):
        color = "#22c55e" if ok else "#f97316"
        self.status_label.configure(text=status, foreground=color)
        self.counter_label.configure(
            text=f"Correct: {self.correct_count}   |   Corrupted: {self.corrupted_count}"
        )

    def clear_reset(self):
        """Clear all logs and reset counters/status (like clearing terminal)."""
        self.log.delete("1.0", "end")
        self.correct_count = 0
        self.corrupted_count = 0
        self.status_label.configure(text="Waiting for packets...", foreground="#e5e7eb")
        self.counter_label.configure(text="Correct: 0   |   Corrupted: 0")

    def handle_packet(self, addr, packet: str):
        parts = packet.split("|")
        if len(parts) != 3:
            self.log_line(f"Invalid packet from {addr}: {packet}")
            self.log_line("-" * 40)
            return

        data, method, incoming = parts
        try:
            computed = generate_control(data, method)
        except Exception as e:
            self.log_line(f"Error computing control for {addr}: {e}")
            self.log_line("-" * 40)
            return

        ok = computed == incoming
        if ok:
            self.correct_count += 1
            status = "DATA CORRECT"
        else:
            self.corrupted_count += 1
            status = "DATA CORRUPTED"

        self.update_status(status, ok)
        self.log_line(f"Packet from {addr}:")
        self.log_line(f"  Data            : {data}")
        self.log_line(f"  Method          : {method}")
        self.log_line(f"  Sent Check Bits : {incoming}")
        self.log_line(f"  Computed Check  : {computed}")
        self.log_line(f"  Status          : {status}")
        self.log_line(
            f"  Counters        : correct={self.correct_count}, corrupted={self.corrupted_count}"
        )
        self.log_line("-" * 40)

    def listen_loop(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((LISTEN_HOST, LISTEN_PORT))
            srv.listen(5)
            self.root.after(
                0,
                lambda: self.status_label.configure(
                    text=f"Listening on {LISTEN_HOST}:{LISTEN_PORT}",
                    foreground="#e5e7eb",
                ),
            )
            while True:
                conn, addr = srv.accept()
                with conn:
                    packet = conn.recv(4096).decode("utf-8")
                    if not packet:
                        continue
                    self.root.after(0, self.handle_packet, addr, packet)


if __name__ == "__main__":
    root = tk.Tk()
    app = ReceiverApp(root)
    root.mainloop()
