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


privkey = x25519.X25519PrivateKey.generate()
privbyte = privkey.private_bytes_raw()
pubkey = privkey.public_key()
pubbyte = pubkey.public_bytes_raw()
wgprivkey = base64.b64encode(privbyte).decode('utf-8')
wgpubkey = base64.b64encode(pubbyte).decode('utf-8')

url = input("URL of ESAServer: ").strip()
if not url.startswith(("http://", "https://")):
    url = "https://" + url

username = input("username: ")
password = input("password: ")

form_data = {
    "username": username,
    "password": password,
    "pubkey": wgpubkey
}


response = requests.post(url, data=form_data)
print(f"\nStatusCode: {response.status_code}")
print("--- SERVER RAW RESPONSE ---")
print(repr(response.text))
print("---------------------------")
conf = genewgconf(response.text, wgprivkey)
filename = "esacli.conf"
with open(filename, "w", encoding="utf-8") as f:
    f.write(conf)
