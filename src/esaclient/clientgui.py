import tkinter as tk
from tkinter import messagebox
import requests
import base64
from cryptography.hazmat.primitives.asymmetric import x25519


def genewgconf(response_text, private_key):
    lines = response_text.strip().splitlines()
    if len(lines) < 5:
        return None

    return f"""[Interface]
PrivateKey = {private_key}
Address = {lines[0]}

[Peer]
PublicKey = {lines[1]}
AllowedIPs = {lines[2]}
Endpoint = {lines[3]}
PersistentKeepalive = {lines[4]}"""


def generate_config():
    url = url_entry.get().strip()
    username = username_entry.get()
    password = password_entry.get()

    if not url:
        messagebox.showerror("错误", "请输入 ESAServer 的 URL")
        return

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        privkey = x25519.X25519PrivateKey.generate()
        privbyte = privkey.private_bytes_raw()
        pubkey = privkey.public_key()
        pubbyte = pubkey.public_bytes_raw()
        wgprivkey = base64.b64encode(privbyte).decode('utf-8')
        wgpubkey = base64.b64encode(pubbyte).decode('utf-8')

        form_data = {
            "username": username,
            "password": password,
            "pubkey": wgpubkey
        }

        submit_btn.config(state=tk.DISABLED, text="请求中...")
        root.update()

        response = requests.post(url, data=form_data)

        result_text.delete(1.0, tk.END)
        result_text.insert(tk.END, f"StatusCode: {response.status_code}\n")
        result_text.insert(tk.END, "--- SERVER RAW RESPONSE ---\n")
        result_text.insert(tk.END, repr(response.text) + "\n")
        result_text.insert(tk.END, "---------------------------\n")

        conf = genewgconf(response.text, wgprivkey)

        if conf:
            filename = "esacli.conf"
            with open(filename, "w", encoding="utf-8") as f:
                f.write(conf)
            result_text.insert(tk.END, f"\n配置文件已成功保存至:\n{filename}")
            messagebox.showinfo("成功", f"配置已保存为 {filename}")
        else:
            result_text.insert(tk.END, "\n解析失败：服务器返回的格式不符合预期。")
            messagebox.showerror("错误", "配置文件生成失败，请检查服务器响应。")

    except Exception as e:
        messagebox.showerror("网络或程序错误", str(e))
        result_text.delete(1.0, tk.END)
        result_text.insert(tk.END, f"请求异常:\n{str(e)}")
    finally:
        submit_btn.config(state=tk.NORMAL, text="生成配置文件")


root = tk.Tk()
root.title("ESAClient")
root.geometry("450x550")
root.resizable(False, False)

tk.Label(root, text="URL of ESAServer:", font=("Arial", 10)).pack(pady=(15, 2))
url_entry = tk.Entry(root, width=45)
url_entry.pack(pady=5)

tk.Label(root, text="Username:", font=("Arial", 10)).pack(pady=(10, 2))
username_entry = tk.Entry(root, width=45)
username_entry.pack(pady=5)

tk.Label(root, text="Password:", font=("Arial", 10)).pack(pady=(10, 2))
password_entry = tk.Entry(root, width=45, show="*")
password_entry.pack(pady=5)

submit_btn = tk.Button(root, text="生成配置文件", width=20, height=2, bg="#4CAF50", fg="white",
                       font=("Arial", 10, "bold"), command=generate_config)
submit_btn.pack(pady=20)

tk.Label(root, text="运行日志:", font=("Arial", 10)).pack(pady=(5, 2))
result_text = tk.Text(root, width=50, height=12, bg="#f4f4f4", font=("Consolas", 9))
result_text.pack(pady=5)

root.mainloop()