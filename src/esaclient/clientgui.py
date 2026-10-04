#!/usr/bin/env python3
"""Small, thread-safe WireGuard client for the ESA HTTP endpoint."""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import queue
import secrets
import threading
import time
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from urllib.parse import urlparse

import requests
from cryptography.hazmat.primitives.asymmetric import x25519


DEFAULT_TIMEOUT = 8.0
MAX_RESPONSE_BYTES = 64 * 1024
USER_AGENT = "EdgeSecurityAccess-WireGuard/3.0"


def generate_wg_keypair() -> tuple[str, str]:
    private_key = x25519.X25519PrivateKey.generate()
    private_raw = private_key.private_bytes_raw()
    public_raw = private_key.public_key().public_bytes_raw()
    return base64.b64encode(private_raw).decode("ascii"), base64.b64encode(public_raw).decode("ascii")


def build_signature_payload(username: str, timestamp: str, nonce: str, pubkey: str) -> str:
    return f"username={username}&timestamp={timestamp}&nonce={nonce}&pubkey={pubkey}"


def sign_request(password: str, payload: str) -> str:
    key = hashlib.sha256(password.encode("utf-8")).digest()
    return hmac.new(key, payload.encode("utf-8"), hashlib.sha256).hexdigest()


def normalize_url(value: str) -> str:
    value = value.strip()
    if not value:
        raise ValueError("server URL is required")
    if "://" not in value:
        value = "https://" + value
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("server URL must include an HTTP(S) host")
    return value


def build_wg_config(response_text: str, private_key: str) -> str:
    lines = [line.strip() for line in response_text.splitlines()]
    if len(lines) != 5 or any(not line for line in lines):
        raise ValueError("server returned an invalid WireGuard configuration")
    if not private_key:
        raise ValueError("private key is required")
    return "\n".join(
        [
            "[Interface]",
            f"PrivateKey = {private_key}",
            f"Address = {lines[0]}",
            "",
            "[Peer]",
            f"PublicKey = {lines[1]}",
            f"AllowedIPs = {lines[2]}",
            f"Endpoint = {lines[3]}",
            f"PersistentKeepalive = {lines[4]}",
            "",
        ]
    )


def authenticate(url: str, username: str, password: str, timeout: float, verify_tls: bool) -> str:
    if not username.strip() or not password:
        raise ValueError("username and password are required")
    if not 0 < timeout <= 300:
        raise ValueError("timeout must be between 0 and 300 seconds")
    url = normalize_url(url)
    private_key, public_key = generate_wg_keypair()
    timestamp = str(int(time.time()))
    nonce = secrets.token_urlsafe(24)
    payload = build_signature_payload(username.strip(), timestamp, nonce, public_key)
    form = {
        "username": username.strip(),
        "password": password,
        "pubkey": public_key,
        "timestamp": timestamp,
        "nonce": nonce,
        "signature": sign_request(password, payload),
    }
    response = requests.post(
        url,
        data=form,
        headers={"User-Agent": USER_AGENT},
        timeout=timeout,
        verify=verify_tls,
    )
    response.raise_for_status()
    if len(response.content) > MAX_RESPONSE_BYTES:
        raise ValueError("server response is too large")
    return build_wg_config(response.text, private_key)


def atomic_write(path: str, content: str) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(f".{target.name}.{secrets.token_hex(6)}.tmp")
    try:
        temporary.write_text(content, encoding="utf-8", newline="\n")
        os.chmod(temporary, 0o600)
        os.replace(temporary, target)
    except BaseException:
        try:
            temporary.unlink()
        except OSError:
            pass
        raise


class ESAClientGUI(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("ESA WireGuard Client")
        self.geometry("720x620")
        self.minsize(620, 520)
        self.url_var = tk.StringVar(value="http://127.0.0.1:30001/")
        self.username_var = tk.StringVar()
        self.password_var = tk.StringVar()
        self.timeout_var = tk.StringVar(value=str(DEFAULT_TIMEOUT))
        self.verify_tls_var = tk.BooleanVar(value=True)
        self.status_var = tk.StringVar(value="Ready")
        self.events: queue.Queue[tuple[str, str]] = queue.Queue()
        self.generated_config = ""
        self._build_ui()
        self.after(100, self._drain_events)

    def _build_ui(self) -> None:
        frame = ttk.Frame(self, padding=16)
        frame.pack(fill=tk.BOTH, expand=True)
        frame.columnconfigure(1, weight=1)
        fields = [("Server URL", self.url_var, False), ("Username", self.username_var, False), ("Password", self.password_var, True), ("Timeout", self.timeout_var, False)]
        for row, (label, variable, secret) in enumerate(fields):
            ttk.Label(frame, text=label).grid(row=row, column=0, sticky="w", pady=5, padx=(0, 10))
            ttk.Entry(frame, textvariable=variable, show="*" if secret else "").grid(row=row, column=1, sticky="ew", pady=5)
        ttk.Checkbutton(frame, text="Verify TLS certificate", variable=self.verify_tls_var).grid(row=4, column=1, sticky="w", pady=5)
        actions = ttk.Frame(frame)
        actions.grid(row=5, column=0, columnspan=2, sticky="ew", pady=(10, 10))
        self.connect_button = ttk.Button(actions, text="Connect", command=self._start_connect)
        self.connect_button.pack(side=tk.LEFT)
        self.save_button = ttk.Button(actions, text="Save config", command=self._save_config, state=tk.DISABLED)
        self.save_button.pack(side=tk.LEFT, padx=8)
        ttk.Label(actions, textvariable=self.status_var).pack(side=tk.RIGHT)
        self.log_text = tk.Text(frame, height=20, wrap=tk.WORD, state=tk.DISABLED)
        self.log_text.grid(row=6, column=0, columnspan=2, sticky="nsew")
        frame.rowconfigure(6, weight=1)

    def _append_log(self, message: str) -> None:
        self.log_text.configure(state=tk.NORMAL)
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)
        self.log_text.configure(state=tk.DISABLED)

    def _start_connect(self) -> None:
        try:
            timeout = float(self.timeout_var.get().strip())
        except ValueError:
            messagebox.showwarning("Invalid timeout", "Timeout must be a number.")
            return
        values = (self.url_var.get(), self.username_var.get(), self.password_var.get(), timeout, self.verify_tls_var.get())
        self.connect_button.configure(state=tk.DISABLED)
        self.save_button.configure(state=tk.DISABLED)
        self.status_var.set("Connecting...")
        self._append_log("Generating WireGuard keypair and authenticating...")
        threading.Thread(target=self._connect_worker, args=values, daemon=True).start()

    def _connect_worker(self, url: str, username: str, password: str, timeout: float, verify_tls: bool) -> None:
        try:
            self.events.put(("ok", authenticate(url, username, password, timeout, verify_tls)))
        except requests.RequestException as exc:
            self.events.put(("error", f"request failed: {exc}"))
        except (OSError, ValueError) as exc:
            self.events.put(("error", str(exc)))

    def _drain_events(self) -> None:
        try:
            status, message = self.events.get_nowait()
        except queue.Empty:
            self.after(100, self._drain_events)
            return
        self.connect_button.configure(state=tk.NORMAL)
        if status == "ok":
            self.generated_config = message
            self.save_button.configure(state=tk.NORMAL)
            self.status_var.set("Connected")
            self._append_log("Authentication succeeded; config is ready to save.")
        else:
            self.status_var.set("Failed")
            self._append_log("Error: " + message)
            messagebox.showerror("Connection failed", message)
        self.after(100, self._drain_events)

    def _save_config(self) -> None:
        if not self.generated_config:
            return
        path = filedialog.asksaveasfilename(defaultextension=".conf", initialfile="esaclient.conf", filetypes=[("WireGuard config", "*.conf"), ("All files", "*.*")])
        if not path:
            return
        try:
            atomic_write(path, self.generated_config)
            self._append_log(f"Saved config: {path}")
        except OSError as exc:
            messagebox.showerror("Save failed", str(exc))


if __name__ == "__main__":
    ESAClientGUI().mainloop()
