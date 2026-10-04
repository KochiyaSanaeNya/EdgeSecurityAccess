#!/usr/bin/env python3
"""Tkinter GUI client for EdgeSecurityAccess."""

from __future__ import annotations

import ctypes
import platform
import queue
import threading
import tkinter as tk
from tkinter import filedialog, font, messagebox, ttk

from esa_client import (
    DEFAULT_TIMEOUT,
    AuthConfig,
    authenticate,
    generate_ed25519_keypair,
    write_text_file,
)


BASE_FONT_SIZE = 10
BASE_MONO_FONT_SIZE = 10


def enable_windows_dpi_awareness() -> None:
    if platform.system() != "Windows":
        return

    try:
        ctypes.windll.user32.SetProcessDpiAwarenessContext(-4)
        return
    except (AttributeError, OSError):
        pass

    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(2)
        return
    except (AttributeError, OSError):
        pass

    try:
        ctypes.windll.user32.SetProcessDPIAware()
    except (AttributeError, OSError):
        pass


class ESAClientGUI(tk.Tk):
    def __init__(self) -> None:
        super().__init__()

        self._configure_dpi_and_fonts()

        self.title("EdgeSecurityAccess Client")
        self.geometry(self._scaled_geometry(780, 680))
        self.minsize(self._scale_px(700), self._scale_px(600))

        self.result_queue: queue.Queue[tuple[str, str]] = queue.Queue()

        self.url_var = tk.StringVar(value="http://127.0.0.1:30001/")
        self.username_var = tk.StringVar()
        self.password_var = tk.StringVar()
        self.pubkey_var = tk.StringVar()
        self.private_seed_var = tk.StringVar()
        self.timeout_var = tk.StringVar(value=str(DEFAULT_TIMEOUT))
        self.status_var = tk.StringVar(value="Ready")

        self._build_ui()
        self.after(100, self._poll_queue)

    def _configure_dpi_and_fonts(self) -> None:
        dpi = self.winfo_fpixels("1i")
        self.ui_scale = max(1.0, dpi / 96.0)
        self.tk.call("tk", "scaling", dpi / 72.0)

        family = "Segoe UI"
        if platform.system() == "Windows":
            family = "Microsoft YaHei UI"

        default_font = font.nametofont("TkDefaultFont")
        default_font.configure(family=family, size=BASE_FONT_SIZE)
        text_font = font.nametofont("TkTextFont")
        text_font.configure(family=family, size=BASE_FONT_SIZE)
        fixed_font = font.nametofont("TkFixedFont")
        fixed_font.configure(size=BASE_MONO_FONT_SIZE)

        style = ttk.Style(self)
        style.configure("TLabel", font=default_font)
        style.configure("TButton", font=default_font, padding=self._scale_padding((8, 4)))
        style.configure("TEntry", font=default_font)
        style.configure("TLabelframe.Label", font=default_font)

    def _scale_px(self, value: int) -> int:
        return round(value * self.ui_scale)

    def _scale_padding(self, values: tuple[int, ...]) -> tuple[int, ...]:
        return tuple(self._scale_px(value) for value in values)

    def _scaled_geometry(self, width: int, height: int) -> str:
        return f"{self._scale_px(width)}x{self._scale_px(height)}"

    def _build_ui(self) -> None:
        root = ttk.Frame(self, padding=self._scale_px(12))
        root.pack(fill=tk.BOTH, expand=True)

        form = ttk.LabelFrame(root, text="Authentication", padding=10)
        form.pack(fill=tk.X)
        form.columnconfigure(1, weight=1)

        ttk.Label(form, text="Server URL").grid(row=0, column=0, sticky=tk.W, pady=4)
        ttk.Entry(form, textvariable=self.url_var).grid(
            row=0, column=1, columnspan=3, sticky=tk.EW, pady=4
        )

        ttk.Label(form, text="Username").grid(row=1, column=0, sticky=tk.W, pady=4)
        ttk.Entry(form, textvariable=self.username_var).grid(
            row=1, column=1, sticky=tk.EW, pady=4
        )

        ttk.Label(form, text="Password").grid(row=1, column=2, sticky=tk.W, padx=(10, 0), pady=4)
        ttk.Entry(form, textvariable=self.password_var, show="*").grid(
            row=1, column=3, sticky=tk.EW, pady=4
        )

        ttk.Label(form, text="Timeout").grid(row=2, column=0, sticky=tk.W, pady=4)
        ttk.Entry(form, textvariable=self.timeout_var, width=12).grid(
            row=2, column=1, sticky=tk.W, pady=4
        )

        key_frame = ttk.LabelFrame(root, text="Ed25519 Key", padding=10)
        key_frame.pack(fill=tk.X, pady=(10, 0))
        key_frame.columnconfigure(1, weight=1)

        ttk.Label(key_frame, text="Public Key").grid(row=0, column=0, sticky=tk.W, pady=4)
        ttk.Entry(key_frame, textvariable=self.pubkey_var).grid(
            row=0, column=1, sticky=tk.EW, pady=4
        )

        ttk.Button(
            key_frame,
            text="Generate Keypair",
            command=self._generate_keypair,
        ).grid(row=0, column=2, padx=(8, 0), pady=4)

        ttk.Label(key_frame, text="Private Seed").grid(row=1, column=0, sticky=tk.W, pady=4)
        ttk.Entry(key_frame, textvariable=self.private_seed_var, show="*").grid(
            row=1, column=1, sticky=tk.EW, pady=4
        )

        ttk.Button(
            key_frame,
            text="Save Keys",
            command=self._save_keys,
        ).grid(row=1, column=2, padx=(8, 0), pady=4)

        ttk.Label(
            key_frame,
            text="Private Seed is shown for saving your tinc identity. Keep it secret.",
        ).grid(row=2, column=1, columnspan=2, sticky=tk.W, pady=(2, 0))

        action_frame = ttk.Frame(root)
        action_frame.pack(fill=tk.X, pady=(10, 0))

        self.auth_button = ttk.Button(
            action_frame,
            text="Authenticate",
            command=self._authenticate,
        )
        self.auth_button.pack(side=tk.LEFT)

        ttk.Button(
            action_frame,
            text="Save Result",
            command=self._save_result,
        ).pack(side=tk.LEFT, padx=(8, 0))

        ttk.Label(action_frame, textvariable=self.status_var).pack(side=tk.RIGHT)

        output_frame = ttk.LabelFrame(root, text="Result", padding=10)
        output_frame.pack(fill=tk.BOTH, expand=True, pady=(10, 0))
        output_frame.rowconfigure(0, weight=1)
        output_frame.columnconfigure(0, weight=1)

        self.output = tk.Text(
            output_frame,
            wrap=tk.WORD,
            height=16,
            font=font.nametofont("TkFixedFont"),
        )
        self.output.grid(row=0, column=0, sticky=tk.NSEW)

        scrollbar = ttk.Scrollbar(output_frame, orient=tk.VERTICAL, command=self.output.yview)
        scrollbar.grid(row=0, column=1, sticky=tk.NS)
        self.output.configure(yscrollcommand=scrollbar.set)

    def _generate_keypair(self) -> None:
        public_key, private_seed = generate_ed25519_keypair()
        self.pubkey_var.set(public_key)
        self.private_seed_var.set(private_seed)
        self.status_var.set("Generated new Ed25519 keypair")

    def _save_keys(self) -> None:
        public_key = self.pubkey_var.get().strip()
        private_seed = self.private_seed_var.get().strip()
        if not public_key or not private_seed:
            messagebox.showwarning("Missing keys", "Generate a keypair first.")
            return

        path = filedialog.asksaveasfilename(
            title="Save keypair",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
        )
        if not path:
            return

        try:
            write_text_file(
                path,
                "Ed25519PublicKey = "
                + public_key
                + "\nEd25519PrivateSeed = "
                + private_seed
                + "\n",
            )
            self.status_var.set(f"Saved keys to {path}")
        except OSError as exc:
            messagebox.showerror("Save failed", str(exc))

    def _authenticate(self) -> None:
        url = self.url_var.get().strip()
        username = self.username_var.get().strip()
        password = self.password_var.get()
        pubkey = self.pubkey_var.get().strip()

        if not pubkey:
            public_key, private_seed = generate_ed25519_keypair()
            self.pubkey_var.set(public_key)
            self.private_seed_var.set(private_seed)
            pubkey = public_key

        if not url or not username or not password:
            messagebox.showwarning("Missing input", "URL, username, and password are required.")
            return

        try:
            timeout = float(self.timeout_var.get().strip())
        except ValueError:
            messagebox.showwarning("Invalid timeout", "Timeout must be a number.")
            return

        if "://" not in url:
            url = "https://" + url

        self.auth_button.configure(state=tk.DISABLED)
        self.status_var.set("Authenticating...")
        self.output.delete("1.0", tk.END)

        thread = threading.Thread(
            target=self._authenticate_worker,
            args=(url, username, password, pubkey, timeout),
            daemon=True,
        )
        thread.start()

    def _authenticate_worker(
        self,
        url: str,
        username: str,
        password: str,
        pubkey: str,
        timeout: float,
    ) -> None:
        try:
            body = authenticate(url, username, password, pubkey, timeout)
            output = AuthConfig.from_response(body).as_tinc_summary()
            self.result_queue.put(("ok", output))
        except Exception as exc:  # noqa: BLE001 - show GUI-friendly error
            self.result_queue.put(("error", str(exc)))

    def _poll_queue(self) -> None:
        try:
            status, message = self.result_queue.get_nowait()
        except queue.Empty:
            self.after(100, self._poll_queue)
            return

        self.auth_button.configure(state=tk.NORMAL)
        if status == "ok":
            self.output.delete("1.0", tk.END)
            self.output.insert(tk.END, message + "\n")
            self.status_var.set("Authentication succeeded")
        else:
            self.output.delete("1.0", tk.END)
            self.output.insert(tk.END, "Error: " + message + "\n")
            self.status_var.set("Authentication failed")

        self.after(100, self._poll_queue)

    def _save_result(self) -> None:
        content = self.output.get("1.0", tk.END).strip()
        if not content:
            messagebox.showwarning("No result", "There is no result to save.")
            return

        path = filedialog.asksaveasfilename(
            title="Save result",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
        )
        if not path:
            return

        try:
            write_text_file(path, content + "\n")
            self.status_var.set(f"Saved result to {path}")
        except OSError as exc:
            messagebox.showerror("Save failed", str(exc))


if __name__ == "__main__":
    enable_windows_dpi_awareness()
    app = ESAClientGUI()
    app.mainloop()
