#!/usr/bin/env python3
"""
MeshCore EthernetBridge relay service.

Two operating modes:

─── UDP RELAY MODE (default) ────────────────────────────────────────────────
Acts as a UDP relay server so mesh nodes with EthernetBridge (unicast mode)
can bridge across the internet. Requires a server with a stable public IP.

Usage:
    python3 bridge_relay.py [--port 5005] [--bind 0.0.0.0]
                            [--peer IP:PORT ...]
                            [--peer-timeout 300] [--keepalive-interval 30]
                            [--mqtt-host HOST] [--mqtt-port 1883]
                            [--mqtt-topic meshcore/bridge]
                            [--mqtt-user USER] [--mqtt-pass PASS]
                            [--channel NAME:SECRET_HEX ...]
                            [--hex] [--quiet]

─── MQTT TRANSPORT MODE (--mqtt-transport) ──────────────────────────────────
Bridges local LAN EthernetBridge broadcasts to/from a shared MQTT broker.
No server with a stable public IP required — both sites can be behind NAT
with rotating IPs since all connections are outbound TCP to the broker.

Run one instance per site, each with the same --network-id but a unique
--site-id. EthernetBridge stays in default broadcast mode; no firmware
IP configuration changes needed.

Usage:
    python3 bridge_relay.py --mqtt-transport
                            --mqtt-host BROKER_HOSTNAME
                            [--mqtt-port 8883] [--mqtt-tls]
                            [--mqtt-user USER] [--mqtt-pass PASS]
                            [--network-id mynetwork]
                            [--site-id siteA]
                            [--port 5005] [--mqtt-topic meshcore/bridge]
                            [--channel NAME:SECRET_HEX ...]
                            [--hex] [--quiet]

MQTT transport topics:
    {prefix}/{network-id}/{site-id}/frames   TX: frames from this site
    {prefix}/{network-id}/+/frames           RX: frames from all sites
    {prefix}/{network-id}/raw                monitoring (meshcoretomqtt compat)
    {prefix}/{network-id}/decoded            monitoring (JSON decoded)

Wire format (EthernetBridge UDP datagram):
    [2]  Magic      0xC03E
    [2]  Length     big-endian, byte count of mesh packet
    [n]  Payload    serialized mesh::Packet
    [2]  Checksum   Fletcher-16 over payload
"""

import socket
import struct
import argparse
import datetime
import sys
import time
import json
import hashlib
import hmac as _hmac_mod

# Optional pycryptodome for channel decryption
try:
    from Crypto.Cipher import AES as _AES
    AES_AVAILABLE = True
except ImportError:
    AES_AVAILABLE = False

# Optional paho-mqtt
try:
    import paho.mqtt.client as mqtt
    MQTT_AVAILABLE = True
except ImportError:
    MQTT_AVAILABLE = False

# ── Constants (mirrors MeshCore.h / Packet.h) ─────────────────────────────────

BRIDGE_MAGIC    = 0xC03E
BRIDGE_OVERHEAD = 6          # magic(2) + length(2) + checksum(2)

PUB_KEY_SIZE         = 32
SIGNATURE_SIZE       = 64
CIPHER_KEY_SIZE      = 16
CIPHER_MAC_SIZE      = 2

ROUTE_TYPE = {
    0x00: "TRANSPORT_FLOOD",
    0x01: "FLOOD",
    0x02: "DIRECT",
    0x03: "TRANSPORT_DIRECT",
}

PAYLOAD_TYPE = {
    0x00: "REQ",
    0x01: "RESPONSE",
    0x02: "TXT_MSG",
    0x03: "ACK",
    0x04: "ADVERT",
    0x05: "GRP_TXT",
    0x06: "GRP_DATA",
    0x07: "ANON_REQ",
    0x08: "PATH",
    0x09: "TRACE",
    0x0A: "MULTIPART",
    0x0B: "CONTROL",
    0x0F: "RAW_CUSTOM",
}

ADV_NODE_TYPE = {0: "unknown", 1: "chat", 2: "repeater", 3: "room", 4: "sensor"}
ADV_LATLON_MASK = 0x10
ADV_NAME_MASK   = 0x80

# ── ANSI colours ──────────────────────────────────────────────────────────────

RESET   = "\033[0m"
BOLD    = "\033[1m"
CYAN    = "\033[36m"
GREEN   = "\033[32m"
YELLOW  = "\033[33m"
MAGENTA = "\033[35m"
RED     = "\033[31m"
DIM     = "\033[2m"


# ── Fletcher-16 ───────────────────────────────────────────────────────────────

def fletcher16(data: bytes) -> int:
    s1, s2 = 0, 0
    for b in data:
        s1 = (s1 + b) % 255
        s2 = (s2 + s1) % 255
    return (s2 << 8) | s1


# ── Bridge frame builders / parsers ───────────────────────────────────────────

# Keepalive: valid frame with zero-length payload (0xC03E 0x0000 0x0000).
# EthernetBridge discards frames where payload_len is too short to hold a
# packet, so this is harmless on the embedded side.
_KEEPALIVE_FRAME = struct.pack(">HHH", BRIDGE_MAGIC, 0, 0)


def build_frame(payload: bytes) -> bytes:
    """Wrap a mesh payload in the bridge framing."""
    length = len(payload)
    header = struct.pack(">HH", BRIDGE_MAGIC, length)
    cs     = fletcher16(payload)
    trailer = struct.pack(">H", cs)
    return header + payload + trailer


def parse_frame(data: bytes) -> bytes | None:
    """
    Validate EthernetBridge framing.
    Returns inner mesh packet bytes, or None on error (silent — caller logs).
    """
    if len(data) < BRIDGE_OVERHEAD:
        return None

    magic = struct.unpack_from(">H", data, 0)[0]
    if magic != BRIDGE_MAGIC:
        return None

    length = struct.unpack_from(">H", data, 2)[0]
    if len(data) < length + BRIDGE_OVERHEAD:
        return None

    payload       = data[4 : 4 + length]
    recv_cs       = struct.unpack_from(">H", data, 4 + length)[0]
    if recv_cs != fletcher16(payload):
        return None

    return payload


# ── Mesh packet decoder (minimal — enough for MQTT decoded topic) ─────────────

def decode_packet(raw: bytes) -> dict | None:
    """Decode a serialized mesh::Packet header, path, and payload bytes."""
    if len(raw) < 2:
        return None

    i = 0
    header       = raw[i]; i += 1
    route_type   = header & 0x03
    payload_type = (header >> 2) & 0x0F
    payload_ver  = (header >> 6) & 0x03

    has_transport = route_type in (0x00, 0x03)
    transport_codes = None
    if has_transport:
        if len(raw) < i + 4:
            return None
        tc0 = struct.unpack_from("<H", raw, i)[0]; i += 2
        tc1 = struct.unpack_from("<H", raw, i)[0]; i += 2
        transport_codes = (tc0, tc1)

    if i >= len(raw):
        return None
    path_len_byte = raw[i]; i += 1
    hash_count = path_len_byte & 0x3F
    hash_size  = (path_len_byte >> 6) + 1
    path = []
    for _ in range(hash_count):
        path.append(raw[i : i + hash_size].hex())
        i += hash_size

    payload = raw[i:]

    result = {
        "route_type":      ROUTE_TYPE.get(route_type, f"0x{route_type:02X}"),
        "payload_type":    PAYLOAD_TYPE.get(payload_type, f"0x{payload_type:02X}"),
        "payload_ver":     payload_ver,
        "transport_codes": list(transport_codes) if transport_codes else None,
        "path":            path,
    }

    # Extra fields for ADVERT packets
    if payload_type == 0x04:
        result.update(_decode_advert_fields(payload))

    # Encrypted header fields
    if payload_type in (0x00, 0x01, 0x02, 0x08) and len(payload) >= 4:
        result["dest_hash"] = payload[0:1].hex()
        result["src_hash"]  = payload[1:2].hex()

    return result


def _decode_advert_fields(payload: bytes) -> dict:
    fields = {}
    if len(payload) < PUB_KEY_SIZE + 4 + SIGNATURE_SIZE:
        return fields
    pub_key = payload[:PUB_KEY_SIZE]
    fields["node_id"] = pub_key[:4].hex()
    fields["pub_key"] = pub_key.hex()
    i = PUB_KEY_SIZE + 4 + SIGNATURE_SIZE  # skip timestamp + sig
    app = payload[i:]
    if app:
        flags     = app[0]
        node_type = flags & 0x0F
        fields["node_type"] = ADV_NODE_TYPE.get(node_type, f"0x{node_type:02X}")
        j = 1
        if flags & ADV_LATLON_MASK and len(app) >= j + 8:
            lat = struct.unpack_from("<i", app, j)[0] / 1_000_000; j += 4
            lon = struct.unpack_from("<i", app, j)[0] / 1_000_000; j += 4
            fields["lat"] = lat
            fields["lon"] = lon
        if flags & ADV_NAME_MASK and j < len(app):
            fields["name"] = app[j:].rstrip(b"\x00").decode("utf-8", errors="replace")
    return fields


# ── Channel decryption (mirrors bridge_monitor.py) ────────────────────────────

def mac_then_decrypt(secret: bytes, src: bytes) -> bytes | None:
    if not AES_AVAILABLE or len(src) <= CIPHER_MAC_SIZE:
        return None
    mac_recv   = src[:CIPHER_MAC_SIZE]
    ciphertext = src[CIPHER_MAC_SIZE:]
    mac_calc   = _hmac_mod.new(secret, ciphertext, hashlib.sha256).digest()[:CIPHER_MAC_SIZE]
    if mac_calc != mac_recv:
        return None
    return _AES.new(secret[:CIPHER_KEY_SIZE], _AES.MODE_ECB).decrypt(ciphertext)


def channel_hash_byte(secret: bytes) -> int:
    if secret[16:32] == bytes(16):
        return hashlib.sha256(secret[:16]).digest()[0]
    return hashlib.sha256(secret).digest()[0]


def parse_channels(channel_args: list) -> tuple:
    channels   = {}
    hash_names = {}
    for arg in (channel_args or []):
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
            secret = secret + bytes(16)
        elif len(secret) != 32:
            print(f"{RED}Channel secret must be 16 or 32 bytes{RESET}", file=sys.stderr)
            sys.exit(1)
        channels[name]  = secret
        hash_names[channel_hash_byte(secret)] = name
    return channels, hash_names


# ── Peer registry ─────────────────────────────────────────────────────────────

STATIC_PEER_TS = float("inf")   # static peers never expire


class PeerRegistry:
    """
    Maps (ip, port) → last_seen timestamp.
    Static peers use last_seen = STATIC_PEER_TS and are never dropped.
    """

    def __init__(self, static_peers: list, timeout: float):
        self._peers: dict = {}
        self._timeout = timeout
        for peer in static_peers:
            self._peers[peer] = STATIC_PEER_TS

    def update(self, addr: tuple):
        """Register or refresh a dynamic peer."""
        if addr not in self._peers or self._peers[addr] != STATIC_PEER_TS:
            self._peers[addr] = time.monotonic()

    def expire(self) -> int:
        """Remove timed-out dynamic peers. Returns number removed."""
        now   = time.monotonic()
        stale = [a for a, ts in self._peers.items()
                 if ts != STATIC_PEER_TS and now - ts > self._timeout]
        for a in stale:
            del self._peers[a]
        return len(stale)

    def others(self, source: tuple) -> list:
        """Return all peer addresses except *source*."""
        return [a for a in self._peers if a != source]

    def all_addrs(self) -> list:
        return list(self._peers.keys())

    def __len__(self):
        return len(self._peers)


# ── Loopback dedup (MQTT transport mode) ─────────────────────────────────────

class RecentFrameSet:
    """
    TTL-based set of frame content hashes used to suppress loopback echoes.

    When the relay UDP-broadcasts a frame it received from MQTT, the local
    socket may receive that broadcast back.  Hashing and ignoring recently
    sent frames prevents this from being relayed back to MQTT.
    """

    def __init__(self, ttl: float = 60.0):
        self._entries: dict = {}   # hash_bytes → monotonic timestamp
        self._ttl = ttl

    @staticmethod
    def _hash(data: bytes) -> bytes:
        return hashlib.sha1(data).digest()[:8]

    def add(self, data: bytes):
        self._entries[self._hash(data)] = time.monotonic()

    def contains(self, data: bytes) -> bool:
        return self._hash(data) in self._entries

    def expire(self):
        now   = time.monotonic()
        stale = [h for h, ts in self._entries.items() if now - ts > self._ttl]
        for h in stale:
            del self._entries[h]


# ── MQTT helpers ──────────────────────────────────────────────────────────────

def make_mqtt_client(host: str, port: int, user: str | None, password: str | None,
                     tls: bool = False,
                     on_message_cb=None) -> "mqtt.Client | None":
    if not MQTT_AVAILABLE:
        print(f"{RED}paho-mqtt is not installed. Install with: pip install paho-mqtt{RESET}",
              file=sys.stderr)
        return None
    client = mqtt.Client()
    if tls:
        client.tls_set()   # uses system CA bundle
    if user:
        client.username_pw_set(user, password or "")
    if on_message_cb is not None:
        client.on_message = on_message_cb
    try:
        client.connect(host, port, keepalive=60)
        client.loop_start()
        return client
    except Exception as exc:
        print(f"{YELLOW}MQTT connect failed ({exc}); continuing without MQTT.{RESET}")
        return None


def mqtt_publish_packet(client, prefix: str, src_addr: tuple,
                        raw_data: bytes, decoded: dict | None,
                        monitoring_prefix: str | None = None):
    """
    Publish raw + decoded monitoring packets.

    monitoring_prefix overrides the topic root for the raw/decoded topics
    (used in MQTT transport mode where topics are network-scoped).
    """
    if client is None:
        return
    mon = monitoring_prefix if monitoring_prefix is not None else prefix
    ts = time.time()
    base = {"src_ip": src_addr[0], "src_port": src_addr[1], "ts": ts}

    # Raw frame
    raw_payload = {**base, "frame_hex": raw_data.hex(), "frame_len": len(raw_data)}
    try:
        client.publish(f"{mon}/raw", json.dumps(raw_payload), qos=0)
    except Exception:
        pass

    # Decoded fields
    if decoded is not None:
        dec_payload = {**base, **decoded}
        try:
            client.publish(f"{mon}/decoded", json.dumps(dec_payload), qos=0)
        except Exception:
            pass


# ── Console pretty-print ──────────────────────────────────────────────────────

def hexdump(data: bytes, indent: str = "    ") -> str:
    lines = []
    for off in range(0, len(data), 16):
        chunk      = data[off : off + 16]
        hex_part   = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{indent}{off:04x}  {hex_part:<48}  {ascii_part}")
    return "\n".join(lines)


def log_packet(src_addr: tuple, relayed_to: list, decoded: dict | None,
               raw_payload: bytes, show_hex: bool, mqtt_ok: bool):
    now   = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
    relay_str = (", ".join(f"{ip}:{p}" for ip, p in relayed_to)
                 if relayed_to else f"{DIM}(no peers to relay to){RESET}")
    mqtt_tag  = f" {DIM}[mqtt]{RESET}" if mqtt_ok else ""

    print(f"\n{BOLD}{CYAN}[{now}]{RESET} {BOLD}{src_addr[0]}:{src_addr[1]}{RESET}"
          f"{mqtt_tag}")
    print(f"  {BOLD}Relay→:{RESET} {relay_str}")

    if decoded:
        ptype = decoded.get("payload_type", "?")
        rtype = decoded.get("route_type",   "?")
        print(f"  {BOLD}Type:{RESET}  {YELLOW}{ptype}{RESET}  {DIM}({rtype}){RESET}")
        if decoded.get("path"):
            print(f"  {BOLD}Path:{RESET}  [{' → '.join(decoded['path'])}]")
        if "name" in decoded:
            print(f"  {BOLD}Node:{RESET}  {GREEN}{decoded['name']}{RESET}"
                  f"  {DIM}[{decoded.get('node_type','')}]{RESET}")
        if "node_id" in decoded:
            print(f"  {BOLD}ID:{RESET}    {decoded['node_id']}...")
        if "dest_hash" in decoded:
            print(f"  {BOLD}Dst:{RESET}   {decoded['dest_hash']}  "
                  f"{DIM}src={decoded.get('src_hash','?')}{RESET}")
    else:
        print(f"  {DIM}(undecodable mesh packet, {len(raw_payload)} bytes){RESET}")

    if show_hex:
        print(f"  {DIM}--- raw ({len(raw_payload)} bytes) ---{RESET}")
        print(hexdump(raw_payload))


def log_keepalive(addr: tuple):
    print(f"  {DIM}→ keepalive sent to {addr[0]}:{addr[1]}{RESET}")


def log_mqtt_rx(site_id: str, decoded: dict | None, raw_payload: bytes, show_hex: bool):
    now = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
    print(f"\n{BOLD}{CYAN}[{now}]{RESET} {DIM}← mqtt:{RESET} {BOLD}{site_id}{RESET}")
    if decoded:
        ptype = decoded.get("payload_type", "?")
        rtype = decoded.get("route_type",   "?")
        print(f"  {BOLD}Type:{RESET}  {YELLOW}{ptype}{RESET}  {DIM}({rtype}){RESET}")
        if decoded.get("path"):
            print(f"  {BOLD}Path:{RESET}  [{' → '.join(decoded['path'])}]")
        if "name" in decoded:
            print(f"  {BOLD}Node:{RESET}  {GREEN}{decoded['name']}{RESET}"
                  f"  {DIM}[{decoded.get('node_type','')}]{RESET}")
    if show_hex:
        print(f"  {DIM}--- raw ({len(raw_payload)} bytes) ---{RESET}")
        print(hexdump(raw_payload))


# ── MQTT transport mode ───────────────────────────────────────────────────────

def run_mqtt_transport(args, sock: socket.socket):
    """
    MQTT transport mode: bridge local LAN UDP broadcasts to/from an MQTT
    broker.  Both sites can be behind NAT with rotating IPs.

    EthernetBridge must stay in its default broadcast mode
    (ETHERNET_BRIDGE_DEST_IP = 255.255.255.255).  No firmware changes needed.
    """
    if not MQTT_AVAILABLE:
        print(f"{RED}paho-mqtt is required for --mqtt-transport. "
              f"Install with: pip install paho-mqtt{RESET}", file=sys.stderr)
        sys.exit(1)
    if not args.mqtt_host:
        print(f"{RED}--mqtt-host is required with --mqtt-transport{RESET}", file=sys.stderr)
        sys.exit(1)

    import socket as _socket_mod
    site_id    = args.site_id or _socket_mod.gethostname()
    network_id = args.network_id

    own_tx_topic  = f"{args.mqtt_topic}/{network_id}/{site_id}/frames"
    sub_topic     = f"{args.mqtt_topic}/{network_id}/+/frames"
    monitor_pfx   = f"{args.mqtt_topic}/{network_id}"

    # Broadcast destination for injecting frames into the local LAN
    bcast_addr = ("255.255.255.255", args.port)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    dedup    = RecentFrameSet(ttl=60.0)
    stats    = {"udp_rx": 0, "mqtt_rx": 0, "bad": 0}
    last_hk  = time.monotonic()

    channels, _ = parse_channels(args.channel)

    def on_message(client, userdata, msg):
        """Called from paho's background thread when a frame arrives from MQTT."""
        if msg.topic == own_tx_topic:
            return   # echo of own publish — ignore

        data = msg.payload
        raw_mesh = parse_frame(data)
        if raw_mesh is None or len(raw_mesh) == 0:
            return

        if dedup.contains(data):
            return   # already seen (loopback)

        dedup.add(data)
        stats["mqtt_rx"] += 1

        # Extract sender site-id from topic for logging
        parts     = msg.topic.split("/")
        from_site = parts[-2] if len(parts) >= 2 else "?"

        try:
            sock.sendto(data, bcast_addr)
        except OSError as exc:
            if not args.quiet:
                print(f"  {YELLOW}UDP broadcast failed: {exc}{RESET}")
            return

        if not args.quiet:
            decoded = decode_packet(raw_mesh)
            log_mqtt_rx(from_site, decoded, raw_mesh, args.hex)

    mqtt_client = make_mqtt_client(
        args.mqtt_host, args.mqtt_port,
        args.mqtt_user, args.mqtt_pass,
        tls=args.mqtt_tls,
        on_message_cb=on_message,
    )
    if mqtt_client is None:
        sys.exit(1)

    mqtt_client.subscribe(sub_topic, qos=0)

    print(f"{BOLD}MeshCore bridge relay{RESET}  [{YELLOW}MQTT transport mode{RESET}]")
    print(f"  {BOLD}Site:{RESET}      {site_id}")
    print(f"  {BOLD}Network:{RESET}   {network_id}")
    print(f"  {BOLD}Broker:{RESET}    {args.mqtt_host}:{args.mqtt_port}"
          f"{'  (TLS)' if args.mqtt_tls else ''}")
    print(f"  {BOLD}TX topic:{RESET}  {own_tx_topic}")
    print(f"  {BOLD}RX topic:{RESET}  {sub_topic}")
    print(f"  {BOLD}UDP:{RESET}       listening on port {args.port}, "
          f"broadcasting to {bcast_addr[0]}")
    print()

    try:
        while True:
            now = time.monotonic()

            # Housekeeping: expire old dedup entries
            if now - last_hk >= 10.0:
                dedup.expire()
                last_hk = now

            # Receive from local EthernetBridge
            try:
                data, addr = sock.recvfrom(512)
            except socket.timeout:
                continue

            stats["udp_rx"] += 1

            raw_mesh = parse_frame(data)
            if raw_mesh is None or len(raw_mesh) == 0:
                stats["bad"] += 1
                continue

            if dedup.contains(data):
                continue   # own broadcast echo

            dedup.add(data)

            # Publish to MQTT transport topic (relays to remote sites)
            try:
                mqtt_client.publish(own_tx_topic, data, qos=0)
            except Exception as exc:
                if not args.quiet:
                    print(f"  {YELLOW}MQTT publish failed: {exc}{RESET}")

            # Decode and publish to monitoring topics
            decoded = decode_packet(raw_mesh)
            mqtt_publish_packet(mqtt_client, args.mqtt_topic, addr, data, decoded,
                                monitoring_prefix=monitor_pfx)

            if not args.quiet:
                log_packet(addr, [], decoded, raw_mesh, args.hex, mqtt_ok=True)

    except KeyboardInterrupt:
        print(f"\n{DIM}Stats: udp_rx={stats['udp_rx']} mqtt_rx={stats['mqtt_rx']} "
              f"bad={stats['bad']}{RESET}")
        mqtt_client.loop_stop()
        mqtt_client.disconnect()
        sys.exit(0)


# ── Argument parsing ──────────────────────────────────────────────────────────

def parse_peer_arg(s: str) -> tuple:
    """Parse 'IP:PORT' into (ip_str, port_int)."""
    try:
        host, port_str = s.rsplit(":", 1)
        return (host, int(port_str))
    except ValueError:
        raise argparse.ArgumentTypeError(f"Invalid peer '{s}': expected IP:PORT")


def parse_args():
    p = argparse.ArgumentParser(
        description="MeshCore EthernetBridge relay / MQTT transport proxy",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    # ── Common ────────────────────────────────────────────────────────────────
    p.add_argument("--port",  type=int, default=5005,   help="UDP listen port (default: 5005)")
    p.add_argument("--bind",  default="0.0.0.0",        help="Bind address (default: 0.0.0.0)")
    p.add_argument("--mqtt-host",  default=None,  help="MQTT broker hostname")
    p.add_argument("--mqtt-port",  type=int, default=1883, help="MQTT broker port (default: 1883)")
    p.add_argument("--mqtt-topic", default="meshcore/bridge", help="MQTT topic prefix")
    p.add_argument("--mqtt-user",  default=None, help="MQTT username")
    p.add_argument("--mqtt-pass",  default=None, help="MQTT password")
    p.add_argument("--mqtt-tls",   action="store_true",
                   help="Enable TLS for MQTT (required by most cloud brokers)")
    p.add_argument("--channel", action="append", metavar="NAME:SECRET_HEX",
                   help="Channel secret for decryption (repeat for multiple)")
    p.add_argument("--hex",   action="store_true", help="Show hex dump in console output")
    p.add_argument("--quiet", action="store_true", help="Suppress per-packet console output")
    # ── MQTT transport mode ───────────────────────────────────────────────────
    p.add_argument("--mqtt-transport", action="store_true",
                   help="Use MQTT as internet backbone (no public IP needed)")
    p.add_argument("--site-id",    default=None,
                   help="Unique name for this site (default: hostname)")
    p.add_argument("--network-id", default="default",
                   help="Shared network namespace on the broker (default: 'default')")
    # ── UDP relay mode ────────────────────────────────────────────────────────
    p.add_argument("--peer",  type=parse_peer_arg, action="append", metavar="IP:PORT",
                   help="Static peer address for relay mode (may be repeated)")
    p.add_argument("--peer-timeout", type=float, default=300.0,
                   help="Relay mode: seconds before a dynamic peer expires (default: 300)")
    p.add_argument("--keepalive-interval", type=float, default=30.0,
                   help="Relay mode: seconds between keepalive pings (default: 30)")
    return p.parse_args()


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    args = parse_args()

    channels, _ = parse_channels(args.channel)
    if channels and not AES_AVAILABLE:
        print(f"{YELLOW}Warning: pycryptodome not installed — channel decryption disabled.{RESET}")

    # Set up UDP socket (shared by both modes)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.bind, args.port))
    sock.settimeout(1.0)

    # ── Dispatch ──────────────────────────────────────────────────────────────
    if args.mqtt_transport:
        if args.peer or args.peer_timeout != 300.0 or args.keepalive_interval != 30.0:
            print(f"{YELLOW}Note: --peer / --peer-timeout / --keepalive-interval "
                  f"are ignored in --mqtt-transport mode.{RESET}")
        run_mqtt_transport(args, sock)
        return  # run_mqtt_transport exits via sys.exit on KeyboardInterrupt

    # ── UDP relay mode ────────────────────────────────────────────────────────

    static_peers = args.peer or []
    peers = PeerRegistry(static_peers, args.peer_timeout)

    # Set up MQTT monitoring (optional)
    mqtt_client = None
    if args.mqtt_host:
        mqtt_client = make_mqtt_client(args.mqtt_host, args.mqtt_port,
                                       args.mqtt_user, args.mqtt_pass,
                                       tls=args.mqtt_tls)
        if mqtt_client:
            print(f"{BOLD}MQTT:{RESET} connected to {args.mqtt_host}:{args.mqtt_port}"
                  f"  topic prefix={args.mqtt_topic}")

    print(f"{BOLD}MeshCore bridge relay{RESET}  listening on {args.bind}:{args.port}")
    if static_peers:
        for sp in static_peers:
            print(f"  {DIM}static peer: {sp[0]}:{sp[1]}{RESET}")
    print(f"  {DIM}peer-timeout={args.peer_timeout}s  "
          f"keepalive-interval={args.keepalive_interval}s{RESET}")
    print()

    stats       = {"rx": 0, "bad": 0, "relayed": 0, "keepalives": 0}
    last_expire = time.monotonic()
    last_ka     = time.monotonic()

    try:
        while True:
            now = time.monotonic()

            # ── Housekeeping: expire stale peers ──────────────────────────────
            if now - last_expire >= 10.0:
                removed = peers.expire()
                if removed and not args.quiet:
                    print(f"  {DIM}expired {removed} peer(s). Active peers: {len(peers)}{RESET}")
                last_expire = now

            # ── Housekeeping: keepalive pings ─────────────────────────────────
            if now - last_ka >= args.keepalive_interval:
                for addr in peers.all_addrs():
                    try:
                        sock.sendto(_KEEPALIVE_FRAME, addr)
                        stats["keepalives"] += 1
                    except OSError:
                        pass
                if not args.quiet and peers.all_addrs():
                    print(f"  {DIM}keepalive → {len(peers.all_addrs())} peer(s){RESET}")
                last_ka = now

            # ── Receive ───────────────────────────────────────────────────────
            try:
                data, addr = sock.recvfrom(512)
            except socket.timeout:
                continue

            stats["rx"] += 1

            raw_mesh = parse_frame(data)
            if raw_mesh is None:
                stats["bad"] += 1
                continue

            # Skip zero-length payloads (keepalives) — don't relay them
            if len(raw_mesh) == 0:
                peers.update(addr)
                continue

            # Register / refresh peer
            old_count = len(peers)
            peers.update(addr)
            if len(peers) != old_count and not args.quiet:
                print(f"  {DIM}new peer registered: {addr[0]}:{addr[1]}"
                      f"  (total: {len(peers)}){RESET}")

            # Relay to all other peers
            relayed_to = peers.others(addr)
            for dest in relayed_to:
                try:
                    sock.sendto(data, dest)
                    stats["relayed"] += 1
                except OSError as exc:
                    if not args.quiet:
                        print(f"  {YELLOW}relay to {dest} failed: {exc}{RESET}")

            # Decode for logging / MQTT
            decoded = decode_packet(raw_mesh)

            mqtt_ok = False
            if mqtt_client is not None:
                mqtt_publish_packet(mqtt_client, args.mqtt_topic, addr, data, decoded)
                mqtt_ok = True

            if not args.quiet:
                log_packet(addr, relayed_to, decoded, raw_mesh, args.hex, mqtt_ok)

    except KeyboardInterrupt:
        print(f"\n{DIM}Stats: rx={stats['rx']} bad={stats['bad']} "
              f"relayed={stats['relayed']} keepalives={stats['keepalives']}{RESET}")
        if mqtt_client:
            mqtt_client.loop_stop()
            mqtt_client.disconnect()
        sys.exit(0)


if __name__ == "__main__":
    main()
