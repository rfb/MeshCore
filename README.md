## About MeshCore

MeshCore is a lightweight, portable C++ library that enables multi-hop packet routing for embedded projects using LoRa and other packet radios. It is designed for developers who want to create resilient, decentralized communication networks that work without the internet.

## 🔍 What is MeshCore?

MeshCore now supports a range of LoRa devices, allowing for easy flashing without the need to compile firmware manually. Users can flash a pre-built binary using tools like Adafruit ESPTool and interact with the network through a serial console.
MeshCore provides the ability to create wireless mesh networks, similar to Meshtastic and Reticulum but with a focus on lightweight multi-hop packet routing for embedded projects. Unlike Meshtastic, which is tailored for casual LoRa communication, or Reticulum, which offers advanced networking, MeshCore balances simplicity with scalability, making it ideal for custom embedded solutions., where devices (nodes) can communicate over long distances by relaying messages through intermediate nodes. This is especially useful in off-grid, emergency, or tactical situations where traditional communication infrastructure is unavailable.

## ⚡ Key Features

* Multi-Hop Packet Routing
  * Devices can forward messages across multiple nodes, extending range beyond a single radio's reach.
  * Supports up to a configurable number of hops to balance network efficiency and prevent excessive traffic.
  * Nodes use fixed roles where "Companion" nodes are not repeating messages at all to prevent adverse routing paths from being used.
* Supports LoRa Radios – Works with Heltec, RAK Wireless, and other LoRa-based hardware.
* Decentralized & Resilient – No central server or internet required; the network is self-healing.
* Low Power Consumption – Ideal for battery-powered or solar-powered devices.
* Simple to Deploy – Pre-built example applications make it easy to get started.

## 🎯 What Can You Use MeshCore For?

* Off-Grid Communication: Stay connected even in remote areas.
* Emergency Response & Disaster Recovery: Set up instant networks where infrastructure is down.
* Outdoor Activities: Hiking, camping, and adventure racing communication.
* Tactical & Security Applications: Military, law enforcement, and private security use cases.
* IoT & Sensor Networks: Collect data from remote sensors and relay it back to a central location.

## 🚀 How to Get Started

- Watch the [MeshCore Intro Video](https://www.youtube.com/watch?v=t1qne8uJBAc) by Andy Kirby.
- Read through our [Frequently Asked Questions](./docs/faq.md) section.
- Flash the MeshCore firmware on a supported device.
- Connect with a supported client.

For developers;

- Install [PlatformIO](https://docs.platformio.org) in [Visual Studio Code](https://code.visualstudio.com).
- Clone and open the MeshCore repository in Visual Studio Code.
- See the example applications you can modify and run:
  - [Companion Radio](./examples/companion_radio) - For use with an external chat app, over BLE, USB or WiFi.
  - [KISS Modem](./examples/kiss_modem) - Serial KISS protocol bridge for host applications. ([protocol docs](./docs/kiss_modem_protocol.md))
  - [Simple Repeater](./examples/simple_repeater) - Extends network coverage by relaying messages.
  - [Simple Room Server](./examples/simple_room_server) - A simple BBS server for shared Posts.
  - [Simple Secure Chat](./examples/simple_secure_chat) - Secure terminal based text communication between devices.
  - [Simple Sensor](./examples/simple_sensor) - Remote sensor node with telemetry and alerting.

The Simple Secure Chat example can be interacted with through the Serial Monitor in Visual Studio Code, or with a Serial USB Terminal on Android.

## ⚡️ MeshCore Flasher

We have prebuilt firmware ready to flash on supported devices.

- Launch https://flasher.meshcore.co.uk
- Select a supported device
- Flash one of the firmware types:
  - Companion, Repeater or Room Server
- Once flashing is complete, you can connect with one of the MeshCore clients below.

## 📱 MeshCore Clients

**Companion Firmware**

The companion firmware can be connected to via BLE, USB or WiFi depending on the firmware type you flashed.

- Web: https://app.meshcore.nz
- Android: https://play.google.com/store/apps/details?id=com.liamcottle.meshcore.android
- iOS: https://apps.apple.com/us/app/meshcore/id6742354151?platform=iphone
- NodeJS: https://github.com/liamcottle/meshcore.js
- Python: https://github.com/fdlamotte/meshcore-cli

**Repeater and Room Server Firmware**

The repeater and room server firmwares can be setup via USB in the web config tool.

- https://config.meshcore.dev

They can also be managed via LoRa in the mobile app by using the Remote Management feature.

## 🌉 EthernetBridge & MQTT Transport

This branch adds native Ethernet bridge support for the RAK4631 repeater, a Python toolchain for relaying and monitoring bridge traffic, and MQTT transport mode so two sites can bridge mesh traffic across the internet without either end needing a public IP.

Key additions:
- **`EthernetBridge`** — firmware-side UDP bridge for RAK4631 (broadcast or unicast mode)
- **`bridge_relay.py`** — UDP relay server (requires a public IP) and MQTT transport mode (no public IP needed)
- **`bridge_monitor.py`** — live packet decoder for local bridge traffic
- **`bridge_inject.py`** — inject test messages via UDP or MQTT for debugging

### Prerequisites

```bash
pip install paho-mqtt pycryptodome
```

### Firmware: Building an Ethernet Repeater

Flash the `RAK_4631_repeater_ethernet` PlatformIO environment onto a RAK4631 + W5100S Ethernet module. The bridge runs in UDP broadcast mode by default (dest `255.255.255.255:5005`), so no IP configuration is needed on the device.

```bash
pio run -e RAK_4631_repeater_ethernet --target upload
```

A pre-built firmware artifact is produced on every push to this branch by the **Build RAK4631 Repeater Ethernet** GitHub Actions workflow. Download it from https://github.com/rfb/MeshCore/actions — select the most recent successful run and download the `RAK_4631_repeater_ethernet-*` artifact from the bottom of the run page.

Once flashed, enable the bridge via the config tool at https://config.meshcore.dev or over LoRa using the Remote Management feature in the mobile app.

---

### Connecting Two Sites via a Public MQTT Broker

Run one `bridge_relay.py` instance per site. Both instances connect **outbound** to the broker so neither site needs a public IP or open firewall ports.

**Site A** (e.g. home lab):

```bash
python3 tools/bridge_relay.py \
  --mqtt-transport \
  --mqtt-host broker.hivemq.com \
  --network-id mynetwork \
  --site-id siteA
```

**Site B** (e.g. remote location):

```bash
python3 tools/bridge_relay.py \
  --mqtt-transport \
  --mqtt-host broker.hivemq.com \
  --network-id mynetwork \
  --site-id siteB
```

Each instance listens on UDP port 5005 for local EthernetBridge broadcasts and forwards them to the other site via the broker. The MQTT topics used are:

| Topic | Purpose |
|---|---|
| `meshcore/bridge/mynetwork/siteA/frames` | TX frames from Site A |
| `meshcore/bridge/mynetwork/+/frames` | RX frames from all sites |
| `meshcore/bridge/mynetwork/raw` | Raw frame monitoring (JSON) |
| `meshcore/bridge/mynetwork/decoded` | Decoded packet monitoring (JSON) |

**With TLS** (recommended for anything beyond local testing):

```bash
python3 tools/bridge_relay.py \
  --mqtt-transport \
  --mqtt-host your-broker.example.com \
  --mqtt-port 8883 --mqtt-tls \
  --mqtt-user myuser --mqtt-pass mypass \
  --network-id mynetwork \
  --site-id siteA
```

---

### Monitoring Local Bridge Traffic

`bridge_monitor.py` listens on the local UDP port and decodes every packet the EthernetBridge sends. Run it on the same machine as the repeater (or any machine on the same LAN):

```bash
# Basic — shows packet types, paths, and node names
python3 tools/bridge_monitor.py

# Decrypt group channel messages (hex secret = 32 bytes = 64 hex chars)
# The default MeshCore public channel:
python3 tools/bridge_monitor.py \
  --channel "Public:8b3387e9c5cdea6ac9e5edbaa115cd72"

# Multiple channels + hex dump of raw payloads
python3 tools/bridge_monitor.py \
  --channel "Public:8b3387e9c5cdea6ac9e5edbaa115cd72" \
  --channel "Ops:aabbccdd..." \
  --hex
```

Example output:

```
[14:32:01.412] 192.168.1.42
  Type:  ADVERT  (FLOOD, ver=0)
  Node:  MyRepeater  [repeater]
  ID:    a1b2c3d4...

[14:32:05.881] 192.168.1.42
  Type:    GRP_TXT  (FLOOD, ver=0)
  Channel: Public (0x8b)
  Time:    14:32:05 UTC
  Message: Alice: Hello mesh!
```

---

### Injecting Messages for Debugging

`bridge_inject.py` builds a properly encrypted `GRP_TXT` mesh packet and injects it into a repeater. This is useful for verifying that the bridge is relaying traffic, testing decryption, or simulating mesh traffic without a physical LoRa device.

**Inject via UDP directly to a local repeater** (or to `bridge_relay.py` in relay mode):

```bash
# Send to the local broadcast address — reaches any EthernetBridge on the LAN
python3 tools/bridge_inject.py \
  --sender "TestNode" \
  --message "Hello from inject!" \
  --channel "Public:8b3387e9c5cdea6ac9e5edbaa115cd72" \
  --host 255.255.255.255 \
  --port 5005

# Send to a specific repeater by IP
python3 tools/bridge_inject.py \
  --sender "TestNode" \
  --message "Ping!" \
  --channel "Public:8b3387e9c5cdea6ac9e5edbaa115cd72" \
  --host 192.168.1.42 \
  --port 5005
```

**Inject via the MQTT queue** (message is forwarded by `bridge_relay.py` to all sites):

```bash
python3 tools/bridge_inject.py \
  --sender "TestNode" \
  --message "Hello from MQTT inject!" \
  --channel "Public:8b3387e9c5cdea6ac9e5edbaa115cd72" \
  --mqtt-transport \
  --mqtt-host broker.hivemq.com \
  --network-id mynetwork \
  --site-id injector
```

**Dry-run** — build the packet and print the raw hex without sending anything:

```bash
python3 tools/bridge_inject.py \
  --sender "TestNode" \
  --message "Test" \
  --channel "Public:8b3387e9c5cdea6ac9e5edbaa115cd72" \
  --dry-run
```

**Tip:** Run `bridge_monitor.py` in a separate terminal while injecting to confirm the packet reaches the bridge and is decoded correctly:

```bash
# Terminal 1 — watch for incoming packets
python3 tools/bridge_monitor.py \
  --channel "Public:8b3387e9c5cdea6ac9e5edbaa115cd72"

# Terminal 2 — inject a test message
python3 tools/bridge_inject.py \
  --sender "Debug" --message "Can you see this?" \
  --channel "Public:8b3387e9c5cdea6ac9e5edbaa115cd72" \
  --host 255.255.255.255
```

---

## 🛠 Hardware Compatibility

MeshCore is designed for devices listed in the [MeshCore Flasher](https://flasher.meshcore.co.uk)

## 📜 License

MeshCore is open-source software released under the MIT License. You are free to use, modify, and distribute it for personal and commercial projects.

## Contributing

Please submit PR's using 'dev' as the base branch!
For minor changes just submit your PR and I'll try to review it, but for anything more 'impactful' please open an Issue first and start a discussion. Is better to sound out what it is you want to achieve first, and try to come to a consensus on what the best approach is, especially when it impacts the structure or architecture of this codebase.

Here are some general principals you should try to adhere to:
* Keep it simple. Please, don't think like a high-level lang programmer. Think embedded, and keep code concise, without any unnecessary layers.
* No dynamic memory allocation, except during setup/begin functions.
* Use the same brace and indenting style that's in the core source modules. (A .clang-format is prob going to be added soon, but please do NOT retroactively re-format existing code. This just creates unnecessary diffs that make finding problems harder)

## Road-Map / To-Do

There are a number of fairly major features in the pipeline, with no particular time-frames attached yet. In very rough chronological order:
- [X] Companion radio: UI redesign
- [X] Repeater + Room Server: add ACL's (like Sensor Node has)
- [X] Standardise Bridge mode for repeaters
- [ ] Repeater/Bridge: Standardise the Transport Codes for zoning/filtering
- [X] Core + Repeater: enhanced zero-hop neighbour discovery
- [ ] Core: round-trip manual path support
- [ ] Companion + Apps: support for multiple sub-meshes (and 'off-grid' client repeat mode)
- [ ] Core + Apps: support for LZW message compression
- [ ] Core: dynamic CR (Coding Rate) for weak vs strong hops
- [ ] Core: new framework for hosting multiple virtual nodes on one physical device
- [ ] V2 protocol spec: discussion and consensus around V2 packet protocol, including path hashes, new encryption specs, etc

## 📞 Get Support

- Report bugs and request features on the [GitHub Issues](https://github.com/ripplebiz/MeshCore/issues) page.
- Find additional guides and components on [my site](https://buymeacoffee.com/ripplebiz).
- Join [MeshCore Discord](https://discord.gg/BMwCtwHj5V) to chat with the developers and get help from the community.
