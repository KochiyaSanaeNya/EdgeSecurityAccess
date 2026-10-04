#!/usr/bin/env python3
"""Python client for the EdgeSecurityAccess authentication server."""

from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import hmac
import os
import secrets
import tempfile
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass


DEFAULT_TIMEOUT = 10
MAX_RESPONSE_BYTES = 64 * 1024


P = 2**255 - 19
D = -121665 * pow(121666, P - 2, P) % P
I = pow(2, (P - 1) // 4, P)
B_Y = 4 * pow(5, P - 2, P) % P
B_X = pow((B_Y * B_Y - 1) * pow(D * B_Y * B_Y + 1, P - 2, P), (P + 3) // 8, P)
if (B_X * B_X - (B_Y * B_Y - 1) * pow(D * B_Y * B_Y + 1, P - 2, P)) % P != 0:
    B_X = B_X * I % P
if B_X & 1:
    B_X = P - B_X
BASE_POINT = (B_X, B_Y)
GROUP_ORDER = 2**252 + 27742317777372353535851937790883648493


@dataclass(frozen=True)
class AuthConfig:
    node: str
    user_ip: str
    server_name: str
    server_public_key: str
    subnet: str
    endpoint: str
    tinc_port: str

    @classmethod
    def from_response(cls, body: str) -> "AuthConfig":
        lines = [line.strip() for line in body.splitlines()]
        if len(lines) != 7 or any(not line for line in lines):
            raise ValueError(
                "unexpected server response: expected 7 config lines, "
                f"got {len(lines)}"
            )
        if not lines[0].startswith("u") or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_" for c in lines[0]):
            raise ValueError("server returned an invalid tinc node name")
        try:
            port = int(lines[6])
        except ValueError as exc:
            raise ValueError("server returned an invalid tinc port") from exc
        if not 1 <= port <= 65535:
            raise ValueError("server returned an invalid tinc port")
        return cls(
            node=lines[0],
            user_ip=lines[1],
            server_name=lines[2],
            server_public_key=lines[3],
            subnet=lines[4],
            endpoint=lines[5],
            tinc_port=lines[6],
        )

    def as_tinc_summary(self) -> str:
        return "\n".join(
            [
                f"Node = {self.node}",
                f"UserSubnet = {self.user_ip}",
                f"ServerName = {self.server_name}",
                f"ServerPublicKey = {self.server_public_key}",
                f"NetworkSubnet = {self.subnet}",
                f"Endpoint = {self.endpoint}",
                f"TincPort = {self.tinc_port}",
            ]
        )


def _inv(value: int) -> int:
    return pow(value, P - 2, P)


def _point_add(point_a: tuple[int, int], point_b: tuple[int, int]) -> tuple[int, int]:
    x1, y1 = point_a
    x2, y2 = point_b
    x1x2 = x1 * x2 % P
    y1y2 = y1 * y2 % P
    dxxyy = D * x1x2 * y1y2 % P
    x3 = (x1 * y2 + x2 * y1) * _inv(1 + dxxyy) % P
    y3 = (y1y2 + x1x2) * _inv(1 - dxxyy) % P
    return x3, y3


def _scalar_mult_base(scalar: int) -> tuple[int, int]:
    result = (0, 1)
    addend = BASE_POINT
    while scalar:
        if scalar & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        scalar >>= 1
    return result


def _encode_point(point: tuple[int, int]) -> bytes:
    x, y = point
    encoded = bytearray(y.to_bytes(32, "little"))
    encoded[31] |= (x & 1) << 7
    return bytes(encoded)


def generate_ed25519_keypair() -> tuple[str, str]:
    seed = os.urandom(32)
    digest = bytearray(hashlib.sha512(seed).digest())
    digest[0] &= 248
    digest[31] &= 63
    digest[31] |= 64
    # Ed25519 uses the clamped 256-bit scalar directly. Reducing it modulo
    # the group order changes the public key and produces an unusable tinc
    # identity.
    scalar = int.from_bytes(digest[:32], "little")
    public_key = _encode_point(_scalar_mult_base(scalar))
    return (
        base64.b64encode(public_key).decode("ascii"),
        base64.b64encode(seed).decode("ascii"),
    )


def write_text_file(path: str, content: str) -> None:
    directory = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(directory, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".esa-", dir=directory, text=True)
    try:
        os.chmod(temporary, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as file:
            file.write(content)
            file.flush()
            os.fsync(file.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def build_signature_payload(username: str, timestamp: str, nonce: str, pubkey: str) -> str:
    return (
        f"username={username}"
        f"&timestamp={timestamp}"
        f"&nonce={nonce}"
        f"&pubkey={pubkey}"
    )


def sign_request(password: str, payload: str) -> str:
    key = hashlib.sha256(password.encode("utf-8")).digest()
    return hmac.new(key, payload.encode("utf-8"), hashlib.sha256).hexdigest()


def validate_public_key(value: str) -> str:
    value = value.strip()
    if len(value) not in {43, 44}:
        raise ValueError("public key must be a base64 encoded 32-byte value")
    try:
        decoded = base64.b64decode(value + "=" * (-len(value) % 4), validate=True)
    except ValueError as exc:
        raise ValueError("public key must be valid base64") from exc
    if len(decoded) != 32:
        raise ValueError("public key must encode 32 bytes")
    return value


def authenticate(
    url: str,
    username: str,
    password: str,
    pubkey: str,
    timeout: float,
) -> str:
    parsed_url = urllib.parse.urlparse(url.strip())
    if parsed_url.scheme not in {"http", "https"} or not parsed_url.netloc:
        raise ValueError("url must include an http or https scheme and host")
    if not 0 < timeout <= 300:
        raise ValueError("timeout must be between 0 and 300 seconds")
    if not username or not password or not pubkey:
        raise ValueError("username, password, and pubkey are required")
    pubkey = validate_public_key(pubkey)
    timestamp = str(int(time.time()))
    nonce = secrets.token_urlsafe(24)
    payload = build_signature_payload(username, timestamp, nonce, pubkey)
    signature = sign_request(password, payload)

    form = urllib.parse.urlencode(
        {
            "username": username,
            "password": password,
            "pubkey": pubkey,
            "timestamp": timestamp,
            "nonce": nonce,
            "signature": signature,
        }
    ).encode("utf-8")

    request = urllib.request.Request(
        url,
        data=form,
        method="POST",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "esa-python-client/1.0",
        },
    )

    with urllib.request.urlopen(request, timeout=timeout) as response:
        body = response.read(MAX_RESPONSE_BYTES + 1)
    if len(body) > MAX_RESPONSE_BYTES:
        raise ValueError("server response is too large")
    return body.decode("utf-8")


def read_public_key(value: str | None, path: str | None) -> tuple[str, str | None]:
    if value and path:
        raise ValueError("use either --pubkey or --pubkey-file, not both")
    if path:
        with open(path, "r", encoding="utf-8") as file:
            return validate_public_key(file.read()), None
    if value:
        return validate_public_key(value), None
    public_key, private_seed = generate_ed25519_keypair()
    return public_key, private_seed


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Authenticate to EdgeSecurityAccess and print the returned tinc config."
    )
    parser.add_argument(
        "--url",
        required=True,
        help="authentication endpoint, for example http://127.0.0.1:30001/",
    )
    parser.add_argument("--username", "-u", required=True, help="login username")
    parser.add_argument(
        "--password",
        help="login password; if omitted, the client prompts without echo",
    )
    parser.add_argument(
        "--pubkey",
        help="tinc Ed25519 public key; omitted means generate a new keypair",
    )
    parser.add_argument("--pubkey-file", help="file containing the tinc Ed25519 public key")
    parser.add_argument(
        "--save-keypair",
        help="optional file path to save an automatically generated keypair",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help=f"HTTP timeout in seconds, default: {DEFAULT_TIMEOUT}",
    )
    parser.add_argument(
        "--raw",
        action="store_true",
        help="print the raw server response instead of a labelled summary",
    )
    parser.add_argument(
        "--output",
        "-o",
        help="optional file path to write the output",
    )
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)

    try:
        pubkey, private_seed = read_public_key(args.pubkey, args.pubkey_file)
        if private_seed and args.save_keypair:
            write_text_file(
                args.save_keypair,
                "Ed25519PublicKey = "
                + pubkey
                + "\nEd25519PrivateSeed = "
                + private_seed
                + "\n",
            )
        password = args.password
        if password is None:
            password = getpass.getpass("Password: ")

        body = authenticate(
            url=args.url,
            username=args.username,
            password=password,
            pubkey=pubkey,
            timeout=args.timeout,
        )

        if args.raw:
            output = body.rstrip("\n")
        else:
            output = AuthConfig.from_response(body).as_tinc_summary()

        if args.output:
            with open(args.output, "w", encoding="utf-8") as file:
                file.write(output + "\n")
        else:
            print(output)

        return 0

    except urllib.error.HTTPError as exc:
        message = exc.read(MAX_RESPONSE_BYTES).decode("utf-8", errors="replace").strip()
        print(f"HTTP {exc.code}: {message}", file=sys.stderr)
        return 1
    except urllib.error.URLError as exc:
        print(f"request failed: {exc.reason}", file=sys.stderr)
        return 1
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
