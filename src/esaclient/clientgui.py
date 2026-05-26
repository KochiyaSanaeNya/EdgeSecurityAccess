import base64
import hashlib
import hmac
import secrets
import threading
import time
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
from tkinter import filedialog

import requests

from cryptography.hazmat.primitives.asymmetric import x25519


REQUEST_TIMEOUT = 8
VERIFY_TLS = True
USER_AGENT = "ESAClient-GUI/2.1"


class ESAClientGUI:

    def __init__(self, root):

        self.root = root
        self.root.title("ESA GUI Client")
        self.root.geometry("700x600")
        self.root.resizable(False, False)

        self.build_ui()

    def build_ui(self):

        frame = ttk.Frame(self.root, padding=15)
        frame.pack(fill="both", expand=True)

        title = ttk.Label(
            frame,
            text="ESA WireGuard Client",
            font=("Segoe UI", 18, "bold")
        )
        title.pack(pady=(0, 20))

        # =========================
        # URL
        # =========================

        ttk.Label(frame, text="Server URL:").pack(anchor="w")

        self.url_var = tk.StringVar()

        self.url_entry = ttk.Entry(
            frame,
            textvariable=self.url_var,
            width=80
        )
        self.url_entry.pack(fill="x", pady=(0, 15))

        # =========================
        # USERNAME
        # =========================

        ttk.Label(frame, text="Username:").pack(anchor="w")

        self.username_var = tk.StringVar()

        self.username_entry = ttk.Entry(
            frame,
            textvariable=self.username_var,
            width=80
        )
        self.username_entry.pack(fill="x", pady=(0, 15))

        # =========================
        # PASSWORD
        # =========================

        ttk.Label(frame, text="Password:").pack(anchor="w")

        self.password_var = tk.StringVar()

        self.password_entry = ttk.Entry(
            frame,
            textvariable=self.password_var,
            show="*",
            width=80
        )
        self.password_entry.pack(fill="x", pady=(0, 15))

        # =========================
        # TLS
        # =========================

        self.tls_var = tk.BooleanVar(value=True)

        self.tls_check = ttk.Checkbutton(
            frame,
            text="Verify TLS Certificate",
            variable=self.tls_var
        )
        self.tls_check.pack(anchor="w", pady=(0, 20))

        # =========================
        # BUTTONS
        # =========================

        button_frame = ttk.Frame(frame)
        button_frame.pack(fill="x", pady=(0, 20))

        self.connect_button = ttk.Button(
            button_frame,
            text="Connect",
            command=self.start_connect
        )
        self.connect_button.pack(side="left", padx=(0, 10))

        self.save_button = ttk.Button(
            button_frame,
            text="Save Config",
            command=self.save_config,
            state="disabled"
        )
        self.save_button.pack(side="left")

        # =========================
        # LOG OUTPUT
        # =========================

        ttk.Label(frame, text="Log Output:").pack(anchor="w")

        self.log_text = tk.Text(
            frame,
            height=18,
            bg="#111111",
            fg="#00ff66",
            insertbackground="#00ff66"
        )
        self.log_text.pack(fill="both", expand=True)

        self.generated_config = None

    # =========================
    # LOGGING
    # =========================

    def log(self, text):
        self.log_text.insert("end", text + "\n")
        self.log_text.see("end")

    # =========================
    # WG KEYPAIR
    # =========================

    def generate_wg_keypair(self):

        priv = x25519.X25519PrivateKey.generate()

        priv_raw = priv.private_bytes_raw()
        pub_raw = priv.public_key().public_bytes_raw()

        wg_priv = base64.b64encode(priv_raw).decode()
        wg_pub = base64.b64encode(pub_raw).decode()

        return wg_priv, wg_pub

    # =========================
    # AUTH
    # =========================

    def derive_auth_key(self, password):
        return hashlib.sha256(password.encode()).digest()

    def build_signature_payload(
            self,
            username,
            timestamp,
            nonce,
            pubkey
    ):

        return (
            f"username={username}"
            f"&timestamp={timestamp}"
            f"&nonce={nonce}"
            f"&pubkey={pubkey}"
        )

    def build_signature(self, auth_key, payload):

        sig = hmac.new(
            auth_key,
            payload.encode(),
            hashlib.sha256
        ).digest()

        return sig.hex()

    # =========================
    # CONFIG
    # =========================

    def generate_wg_config(self, response_text, private_key):

        lines = response_text.strip().splitlines()

        if len(lines) < 5:
            raise RuntimeError(
                f"Invalid server response:\n{response_text}"
            )

        return f"""[Interface]
PrivateKey = {private_key}
Address = {lines[0]}

[Peer]
PublicKey = {lines[1]}
AllowedIPs = {lines[2]}
Endpoint = {lines[3]}
PersistentKeepalive = {lines[4]}
"""

    # =========================
    # CONNECT
    # =========================

    def start_connect(self):

        self.connect_button.config(state="disabled")

        threading.Thread(
            target=self.connect,
            daemon=True
        ).start()

    def connect(self):

        try:

            url = self.url_var.get().strip()
            username = self.username_var.get().strip()
            password = self.password_var.get().strip()

            if not url:
                raise RuntimeError("Server URL required")

            if not username:
                raise RuntimeError("Username required")

            if not password:
                raise RuntimeError("Password required")

            if not url.startswith(("http://", "https://")):
                url = "https://" + url

            self.log("[+] Generating WireGuard keypair...")

            wg_priv, wg_pub = self.generate_wg_keypair()

            timestamp = str(int(time.time()))
            nonce = secrets.token_hex(16)

            auth_key = self.derive_auth_key(password)

            payload = self.build_signature_payload(
                username,
                timestamp,
                nonce,
                wg_pub
            )

            signature = self.build_signature(
                auth_key,
                payload
            )

            form_data = {
                "username": username,
                "password": password,
                "pubkey": wg_pub,
                "timestamp": timestamp,
                "nonce": nonce,
                "signature": signature
            }

            headers = {
                "User-Agent": USER_AGENT
            }

            self.log("[+] Connecting to server...")

            response = requests.post(
                url,
                data=form_data,
                headers=headers,
                timeout=REQUEST_TIMEOUT,
                verify=self.tls_var.get()
            )

            self.log(f"[+] StatusCode: {response.status_code}")

            if response.status_code != 200:
                raise RuntimeError(response.text)

            self.generated_config = self.generate_wg_config(
                response.text,
                wg_priv
            )

            self.log("[+] WireGuard config generated")
            self.log("[+] Ready to save")

            self.save_button.config(state="normal")

            messagebox.showinfo(
                "Success",
                "Authentication successful"
            )

        except requests.exceptions.Timeout:
            messagebox.showerror(
                "Error",
                "Request timeout"
            )

        except requests.exceptions.ConnectionError:
            messagebox.showerror(
                "Error",
                "Connection failed"
            )

        except requests.exceptions.SSLError:
            messagebox.showerror(
                "Error",
                "TLS verification failed"
            )

        except Exception as e:
            messagebox.showerror(
                "Error",
                str(e)
            )
            self.log(f"[!] Error: {e}")

        finally:
            self.connect_button.config(state="normal")

    # =========================
    # SAVE CONFIG
    # =========================

    def save_config(self):

        if not self.generated_config:
            return

        path = filedialog.asksaveasfilename(
            title="Save WireGuard Config",
            defaultextension=".conf",
            filetypes=[
                ("WireGuard Config", "*.conf"),
                ("All Files", "*.*")
            ],
            initialfile="esaclient.conf"
        )

        if not path:
            return

        with open(path, "w", encoding="utf-8") as f:
            f.write(self.generated_config)

        self.log(f"[+] Config saved: {path}")

        messagebox.showinfo(
            "Saved",
            "WireGuard config saved successfully"
        )


def main():

    root = tk.Tk()

    try:
        style = ttk.Style()
        style.theme_use("clam")
    except:
        pass

    ESAClientGUI(root)

    root.mainloop()


if __name__ == "__main__":
    main()