#!/usr/bin/env python3
"""
MeshCore EthernetBridge group message injector.

Builds and sends a GRP_TXT (public group channel) mesh packet via UDP or MQTT,
using the same wire format as EthernetBridge and bridge_relay.py.

Requires pycryptodome for encryption:
    pip install pycryptodome

For MQTT mode, also requires paho-mqtt:
    pip install paho-mqtt

Usage examples
──────────────
# Send via UDP direct to relay or local EthernetBridge:
    python3 bridge_inject.py \\
        --sender "Alice" --message "Hello mesh!" \\
        --channel "Default:aabbccdd..." \\
        --host 192.168.1.10 --port 5005

# Send via MQTT transport (mirrors bridge_relay.py --mqtt-transport):
    python3 bridge_inject.py \\
        --sender "Alice" --message "Hello mesh!" \\
        --channel "Default:aabbccdd..." \\
        --mqtt-transport \\
        --mqtt-host broker.example.com \\
        --network-id mynetwork --site-id injector

Wire format (EthernetBridge UDP datagram):
    [2]  Magic      0xC03E  (big-endian)
    [2]  Length     big-endian, byte count of mesh packet
    [n]  Payload    serialized mesh::Packet
    [2]  Checksum   Fletcher-16 over payload

GRP_TXT mesh packet (FLOOD, no path):
    [1]  Header     0x15  (route=FLOOD, payload=GRP_TXT, ver=0)
    [1]  PathLen    0x00  (0 hops, hash_size=1)
    [1]  ChanHash   SHA256(secret)[0]
    [2]  MAC        HMAC-SHA256(secret, ciphertext)[0:2]
    [n]  Ciphertext AES128-ECB, zero-padded to 16-byte blocks

GRP_TXT plaintext:
    [4]  Timestamp  LE uint32 (Unix epoch, seconds)
    [1]  TxtType    0x00  (plain text)
    [n]  Text       "sender: message\\0"  (null-padded to block boundary)
"""

import socket
import struct
import argparse
import hashlib
import hmac
import sys
import time

try:
    from Crypto.Cipher import AES as _AES
    AES_AVAILABLE = True
except ImportError:
    AES_AVAILABLE = False

try:
    import paho.mqtt.client as _mqtt
    MQTT_AVAILABLE = True
except ImportError:
    MQTT_AVAILABLE = False

# ── Constants ─────────────────────────────────────────────────────────────────

BRIDGE_MAGIC     = 0xC03E
CIPHER_KEY_SIZE  = 16   # AES128
CIPHER_MAC_SIZE  = 2    # HMAC prefix bytes kept on wire
CIPHER_BLOCK     = 16

# Mesh packet header for FLOOD / GRP_TXT / ver=0:
#   bits [1:0]  = route_type  = 0x01 (FLOOD)
#   bits [5:2]  = payload_type = 0x05 (GRP_TXT)
#   bits [7:6]  = payload_ver  = 0x00
_MESH_HEADER    = (0x00 << 6) | (0x05 << 2) | 0x01   # 0x15
_MESH_PATH_LEN  = 0x00   # 0 hops, hash_size=1

# ANSI
RESET  = "\033[0m"
BOLD   = "\033[1m"
GREEN  = "\033[32m"
YELLOW = "\033[33m"
RED    = "\033[31m"
DIM    = "\033[2m"

MAX_TEXT_LEN = 200   # matches firmware MAX_TEXT_LEN


# ── Fletcher-16 ───────────────────────────────────────────────────────────────

def fletcher16(data: bytes) -> int:
    s1, s2 = 0, 0
    for b in data:
        s1 = (s1 + b) % 255
        s2 = (s2 + s1) % 255
    return (s2 << 8) | s1


# ── Channel helpers ───────────────────────────────────────────────────────────

def channel_hash_byte(secret: bytes) -> int:
    """
    Mirrors BaseChatMesh::setChannel() hash derivation:
      SHA256(secret[0:16])[0]  if secret[16:32] == all zeros (128-bit key)
      SHA256(secret[0:32])[0]  otherwise (256-bit key)
    """
    if secret[16:32] == bytes(16):
        return hashlib.sha256(secret[:16]).digest()[0]
    return hashlib.sha256(secret).digest()[0]


def parse_channel(arg: str) -> tuple[str, bytes]:
    """Parse 'NAME:HEXSECRET' into (name, secret_bytes)."""
    if ":" not in arg:
        print(f"{RED}--channel must be NAME:SECRET_HEX{RESET}", file=sys.stderr)
        sys.exit(1)
    name, hex_secret = arg.split(":", 1)
    try:
        secret = bytes.fromhex(hex_secret)
    except ValueError:
        print(f"{RED}Invalid hex secret for channel '{name}'{RESET}", file=sys.stderr)
        sys.exit(1)
    if len(secret) == 16:
        secret = secret + bytes(16)   # zero-pad to 32 bytes
    elif len(secret) != 32:
        print(f"{RED}Channel secret must be 16 or 32 bytes, got {len(secret)}{RESET}",
              file=sys.stderr)
        sys.exit(1)
    return name, secret


# ── Packet builders ───────────────────────────────────────────────────────────

def _encrypt_block(key16: bytes, plaintext: bytes) -> bytes:
    """AES128-ECB encrypt, zero-padding last partial block (mirrors Utils::encrypt)."""
    out = b""
    i = 0
    while i < len(plaintext):
        block = plaintext[i:i + CIPHER_BLOCK]
        if len(block) < CIPHER_BLOCK:
            block = block + bytes(CIPHER_BLOCK - len(block))
        cipher = _AES.new(key16, _AES.MODE_ECB)
        out += cipher.encrypt(block)
        i += CIPHER_BLOCK
    return out


def build_grp_txt_plaintext(sender: str, message: str, timestamp: int) -> bytes:
    """
    Build the GRP_TXT plaintext buffer (mirrors BaseChatMesh::sendGroupMessage):
      [timestamp:4 LE][txt_type=0]["sender: message\\0"]
    The null terminator is included; AES block-padding (zeros) is added during encryption.
    """
    text = f"{sender}: {message}\x00"
    text_bytes = text.encode("utf-8")

    # Firmware clamps to MAX_TEXT_LEN for the "sender: message" portion
    max_body = MAX_TEXT_LEN
    if len(text_bytes) > max_body:
        text_bytes = text_bytes[:max_body]
        if not text_bytes.endswith(b"\x00"):
            text_bytes = text_bytes[:-1] + b"\x00"

    return struct.pack("<I", timestamp) + bytes([0x00]) + text_bytes


def build_grp_txt_payload(secret: bytes, plaintext: bytes) -> bytes:
    """
    Encrypt and MAC the plaintext, prepend channel hash.
    Returns the full GRP_TXT payload: [hash:1][mac:2][ciphertext].
    Mirrors Utils::encryptThenMAC and Mesh::createGroupDatagram.
    """
    ch_hash  = channel_hash_byte(secret)
    ct       = _encrypt_block(secret[:CIPHER_KEY_SIZE], plaintext)
    mac      = hmac.new(secret, ct, hashlib.sha256).digest()[:CIPHER_MAC_SIZE]
    return bytes([ch_hash]) + mac + ct


def build_mesh_packet(grp_payload: bytes) -> bytes:
    """Wrap group payload in a minimal FLOOD mesh::Packet (no path hops)."""
    return bytes([_MESH_HEADER, _MESH_PATH_LEN]) + grp_payload


def build_bridge_frame(mesh_packet: bytes) -> bytes:
    """Wrap mesh packet in EthernetBridge UDP framing."""
    header  = struct.pack(">HH", BRIDGE_MAGIC, len(mesh_packet))
    trailer = struct.pack(">H", fletcher16(mesh_packet))
    return header + mesh_packet + trailer


# ── Delivery ──────────────────────────────────────────────────────────────────

def send_udp(frame: bytes, host: str, port: int):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(frame, (host, port))
    finally:
        sock.close()


def send_mqtt(frame: bytes, args):
    if not MQTT_AVAILABLE:
        print(f"{RED}paho-mqtt is required for --mqtt-transport. "
              f"Install with: pip install paho-mqtt{RESET}", file=sys.stderr)
        sys.exit(1)

    import socket as _sock
    site_id    = args.site_id or _sock.gethostname()
    network_id = args.network_id
    topic      = f"{args.mqtt_topic}/{network_id}/{site_id}/frames"

    client = _mqtt.Client()
    if args.mqtt_tls:
        client.tls_set()
    if args.mqtt_user:
        client.username_pw_set(args.mqtt_user, args.mqtt_pass or "")
    client.connect(args.mqtt_host, args.mqtt_port, keepalive=10)
    client.loop_start()
    time.sleep(0.3)   # let the connection establish

    result = client.publish(topic, frame, qos=0)
    result.wait_for_publish(timeout=5.0)

    client.loop_stop()
    client.disconnect()
    return topic


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(
        description="Inject a GRP_TXT message into a MeshCore bridge",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    # Message content
    p.add_argument("--sender",  required=True, help="Sender display name")
    p.add_argument("--message", required=True, help="Message text")
    p.add_argument("--channel", default="Public:8b3387e9c5cdea6ac9e5edbaa115cd72",
                   metavar="NAME:SECRET_HEX",
                   help="Channel secret (16 or 32 bytes as hex) "
                        "(default: MeshCore public channel)")
    p.add_argument("--timestamp", type=int, default=None,
                   help="Unix timestamp to embed (default: current time)")

    # UDP mode
    p.add_argument("--host", default="127.0.0.1",
                   help="UDP destination host (default: 127.0.0.1)")
    p.add_argument("--port", type=int, default=5005,
                   help="UDP destination port (default: 5005)")

    # MQTT transport mode
    p.add_argument("--mqtt-transport", action="store_true",
                   help="Publish via MQTT instead of UDP")
    p.add_argument("--mqtt-host",  default=None)
    p.add_argument("--mqtt-port",  type=int, default=1883)
    p.add_argument("--mqtt-user",  default=None)
    p.add_argument("--mqtt-pass",  default=None)
    p.add_argument("--mqtt-tls",   action="store_true",
                   help="Enable TLS for MQTT connection")
    p.add_argument("--mqtt-topic", default="meshcore/bridge",
                   help="MQTT topic prefix (default: meshcore/bridge)")
    p.add_argument("--network-id", default="default",
                   help="Shared network namespace on broker (default: 'default')")
    p.add_argument("--site-id", default=None,
                   help="Site identifier for MQTT topic (default: hostname)")

    p.add_argument("--dry-run", action="store_true",
                   help="Build packet and print hex without sending")

    args = p.parse_args()

    if not AES_AVAILABLE:
        print(f"{RED}pycryptodome is required. Install with: pip install pycryptodome{RESET}",
              file=sys.stderr)
        sys.exit(1)

    if args.mqtt_transport and not args.mqtt_host:
        print(f"{RED}--mqtt-host is required with --mqtt-transport{RESET}", file=sys.stderr)
        sys.exit(1)

    ch_name, secret = parse_channel(args.channel)
    ts = args.timestamp or int(time.time())

    # Build packet
    plaintext   = build_grp_txt_plaintext(args.sender, args.message, ts)
    grp_payload = build_grp_txt_payload(secret, plaintext)
    mesh_pkt    = build_mesh_packet(grp_payload)
    frame       = build_bridge_frame(mesh_pkt)

    ch_hash = channel_hash_byte(secret)
    print(f"{BOLD}Channel:{RESET}  {GREEN}{ch_name}{RESET}  {DIM}(hash=0x{ch_hash:02x}){RESET}")
    print(f"{BOLD}Sender:{RESET}   {args.sender}")
    print(f"{BOLD}Message:{RESET}  {args.message}")
    print(f"{BOLD}Frame:{RESET}    {len(frame)} bytes  "
          f"{DIM}(mesh={len(mesh_pkt)}, payload={len(grp_payload)}, "
          f"ciphertext={len(grp_payload)-3}){RESET}")

    if args.dry_run:
        print(f"\n{DIM}--- frame hex (dry-run, not sent) ---{RESET}")
        for off in range(0, len(frame), 16):
            chunk = frame[off:off+16]
            print(f"  {off:04x}  {' '.join(f'{b:02x}' for b in chunk)}")
        return

    if args.mqtt_transport:
        topic = send_mqtt(frame, args)
        print(f"{BOLD}Sent:{RESET}     MQTT  {GREEN}{topic}{RESET}")
    else:
        send_udp(frame, args.host, args.port)
        print(f"{BOLD}Sent:{RESET}     UDP → {GREEN}{args.host}:{args.port}{RESET}")


if __name__ == "__main__":
    main()
