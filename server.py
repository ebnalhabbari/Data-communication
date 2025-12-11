# server.py  - Modern GUI Server (with Clear button)

import random
import socket
import threading
import tkinter as tk
from tkinter import ttk

LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 5000   # where sender connects
RECEIVER_HOST = "127.0.0.1"
RECEIVER_PORT = 5001  # where receiver listens


# ========== Error Injection Methods ==========

def bit_flip(s: str) -> str:
    if not s:
        return s
    idx = random.randrange(len(s))
    flipped_char = chr(ord(s[idx]) ^ 0b00000001)
    return s[:idx] + flipped_char + s[idx + 1:]


def char_deletion(s: str) -> str:
    if len(s) <= 1:
        return s
    idx = random.randrange(len(s))
    return s[:idx] + s[idx + 1:]


def random_insertion(s: str) -> str:
    idx = random.randrange(len(s) + 1)
    rnd = chr(random.randint(32, 126))
    return s[:idx] + rnd + s[idx:]


def burst_error(s: str) -> str:
    if len(s) <= 2:
        return s
    start = random.randrange(len(s) - 1)
    length = random.randint(2, min(4, len(s) - start))
    segment = s[start:start + length]
    corrupted = "".join(chr(ord(ch) ^ 0b00000001) for ch in segment)
    return s[:start] + corrupted + s[start + length:]


ERROR_METHODS = [
    ("Bit flip", bit_flip),
    ("Char deletion", char_deletion),
    ("Random insertion", random_insertion),
    ("Burst error", burst_error),
]


def apply_random_error(data: str):
    name, func = random.choice(ERROR_METHODS)
    return func(data), name


# ========== GUI + Server Logic ==========

class ServerApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Server - Data Communication")
        self.root.geometry("660x440")
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
            foreground="#f97316",
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
            text="Server  •  Error Injection Node",
            style="Title.TLabel",
            anchor="center",
        )
        header.pack(fill="x", pady=(10, 4))

        card = tk.Frame(root, bg="#0b1120", highlightthickness=1, highlightbackground="#1f2937")
        card.pack(fill="both", expand=True, padx=14, pady=10)

        self.status_label = ttk.Label(card, text="Starting server...", foreground="#e5e7eb")
        self.status_label.grid(row=0, column=0, sticky="w", padx=10, pady=(10, 4))

        clear_btn = ttk.Button(card, text="Clear", style="Secondary.TButton", command=self.clear_log)
        clear_btn.grid(row=0, column=1, sticky="e", padx=10, pady=(10, 4))

        log_frame = tk.Frame(card, bg="#0b1120")
        log_frame.grid(row=1, column=0, columnspan=2, sticky="nsew", padx=10, pady=(0, 10))

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

        # start server thread
        t = threading.Thread(target=self.server_loop, daemon=True)
        t.start()

    def log_line(self, text: str):
        self.log.insert("end", text + "\n")
        self.log.see("end")

    def clear_log(self):
        self.log.delete("1.0", "end")

    def server_loop(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((LISTEN_HOST, LISTEN_PORT))
            srv.listen(5)
            self.root.after(
                0,
                lambda: self.status_label.config(
                    text=f"Listening on {LISTEN_HOST}:{LISTEN_PORT}"
                ),
            )
            while True:
                conn, addr = srv.accept()
                threading.Thread(target=self.handle_client, args=(conn, addr), daemon=True).start()

    def handle_client(self, conn: socket.socket, addr):
        with conn:
            try:
                packet = conn.recv(4096).decode("utf-8")
                if not packet:
                    return

                parts = packet.split("|")
                if len(parts) != 3:
                    self.root.after(0, self.log_line, f"Invalid packet from {addr}: {packet}")
                    return

                data, method, control = parts
                corrupted, err_name = apply_random_error(data)
                new_packet = f"{corrupted}|{method}|{control}"

                # forward to receiver
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as out:
                    out.connect((RECEIVER_HOST, RECEIVER_PORT))
                    out.sendall(new_packet.encode("utf-8"))

                def gui_log():
                    self.log_line(f"Packet from {addr}:")
                    self.log_line(f"  Original data : {data}")
                    self.log_line(f"  Method        : {method}")
                    self.log_line(f"  Control bits  : {control}")
                    self.log_line(f"  Error applied : {err_name}")
                    self.log_line(f"  New data      : {corrupted}")
                    self.log_line("-" * 40)

                self.root.after(0, gui_log)

            except Exception as e:
                self.root.after(0, self.log_line, f"Error handling {addr}: {e}")


if __name__ == "__main__":
    root = tk.Tk()
    app = ServerApp(root)
    root.mainloop()
