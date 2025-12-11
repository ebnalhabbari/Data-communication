# sender.py  - Modern GUI Sender (with Clear button)

import socket
import tkinter as tk
from tkinter import ttk, messagebox

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 5000  # server listens here

# ========== Error Detection Helpers (compact) ==========

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
        # rows
        for r in range(rows):
            row_bits = blk[r * cols:(r + 1) * cols]
            out.append("1" if row_bits.count("1") % 2 else "0")
        # cols
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


# ========== GUI ==========

class SenderApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Sender - Data Communication")
        self.root.geometry("580x430")
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
            foreground="#38bdf8",
            background="#050816",
        )

        style.configure(
            "Accent.TButton",
            font=("Segoe UI", 10, "bold"),
            padding=6,
            relief="flat",
            background="#22c55e",
            foreground="#020617",
        )
        style.map(
            "Accent.TButton",
            background=[("active", "#16a34a"), ("pressed", "#16a34a")],
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

        # header
        header = ttk.Label(
            root,
            text="Sender  •  Error Detection Demo",
            style="Title.TLabel",
            anchor="center",
        )
        header.pack(fill="x", pady=(10, 4))

        card = tk.Frame(root, bg="#0b1120", bd=0, highlightthickness=1, highlightbackground="#1f2937")
        card.pack(fill="both", expand=True, padx=14, pady=10)

        # message
        ttk.Label(card, text="Message:").grid(row=0, column=0, sticky="w", padx=10, pady=(10, 2))
        self.entry_message = ttk.Entry(card, font=("Segoe UI", 10))
        self.entry_message.grid(row=1, column=0, columnspan=2, sticky="ew", padx=10)

        # method
        ttk.Label(card, text="Error Detection Method:").grid(row=2, column=0, sticky="w", padx=10, pady=(10, 2))
        self.method_box = ttk.Combobox(
            card,
            values=list(METHOD_FUNCS.keys()),
            state="readonly",
            font=("Segoe UI", 10),
        )
        self.method_box.grid(row=3, column=0, sticky="ew", padx=10, pady=(0, 8))
        self.method_box.current(2)  # CRC16 default

        send_btn = ttk.Button(card, text="Send Packet", style="Accent.TButton", command=self.send_packet)
        send_btn.grid(row=3, column=1, padx=(0, 10), pady=(0, 8), sticky="e")

        # log header + clear button
        ttk.Label(card, text="Activity log:").grid(row=4, column=0, sticky="w", padx=10, pady=(4, 2))
        clear_btn = ttk.Button(card, text="Clear", style="Secondary.TButton", command=self.clear_log)
        clear_btn.grid(row=4, column=1, sticky="e", padx=10, pady=(4, 2))

        # log
        log_frame = tk.Frame(card, bg="#0b1120")
        log_frame.grid(row=5, column=0, columnspan=2, sticky="nsew", padx=10, pady=(0, 10))

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

        card.columnconfigure(0, weight=1)
        card.rowconfigure(5, weight=1)

    def log_line(self, text: str):
        self.log.insert("end", text + "\n")
        self.log.see("end")

    def clear_log(self):
        """Clear log and message entry (like cleaning the terminal)."""
        self.log.delete("1.0", "end")
        self.entry_message.delete(0, "end")

    def send_packet(self):
        msg = self.entry_message.get().strip()
        method = self.method_box.get().strip().upper()

        if not msg:
            messagebox.showwarning("Warning", "Please enter a message.")
            return
        if method not in METHOD_FUNCS:
            messagebox.showwarning("Warning", "Please select a method.")
            return

        try:
            control = generate_control(msg, method)
            packet = f"{msg}|{method}|{control}"

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((SERVER_HOST, SERVER_PORT))
                s.sendall(packet.encode("utf-8"))

            self.log_line("Packet sent:")
            self.log_line(f"  Data   : {msg}")
            self.log_line(f"  Method : {method}")
            self.log_line(f"  Control: {control}")
            self.log_line(f"  Raw    : {packet}")
            self.log_line("-" * 40)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to send: {e}")


if __name__ == "__main__":
    root = tk.Tk()
    app = SenderApp(root)
    root.mainloop()
