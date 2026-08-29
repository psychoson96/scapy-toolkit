# Flipper Zero Home-Lab Guide — Testing *Your Own* Network

A practical, hands-on workflow for learning your **Flipper Zero (Momentum firmware)**
with an **ESP32 Wi-Fi Dev Board running Marauder**, and feeding what you find into
this repo's **Scapy toolkit** for the packet-level analysis the Flipper can't do.

> ⚠️ **Scope & authorization.** Everything here is written for testing **networks and
> devices you own or have written permission to test**. Wi-Fi deauth, handshake capture,
> RFID/NFC cloning, and Sub-GHz replay are illegal against systems you don't control —
> in many places even a single deauth frame against someone else's AP is a crime.
> Keep a note of *what* you tested and *when you were authorized*. If you can't point to
> ownership or written permission, don't run it.

---

## Table of contents

1. [How the pieces fit together](#1-how-the-pieces-fit-together)
2. [One-time setup checklist](#2-one-time-setup-checklist)
3. [The core loop: recon → capture → analyze → fix](#3-the-core-loop)
4. [Track A — Wi-Fi (ESP32 + Marauder)](#4-track-a--wi-fi-esp32--marauder)
5. [Track B — the Flipper's own radios (Sub-GHz, NFC, RFID, IR, BadUSB)](#5-track-b--the-flippers-own-radios)
6. [Bridging to the Scapy toolkit](#6-bridging-to-the-scapy-toolkit)
7. [A first hands-on session (60–90 min)](#7-a-first-hands-on-session)
8. [Turning findings into fixes](#8-turning-findings-into-fixes)
9. [Legal & safety notes](#9-legal--safety-notes)
10. [Glossary & further reading](#10-glossary--further-reading)

---

## 1. How the pieces fit together

Your Flipper Zero is a **radio and hardware multitool**, not a network sniffer. It's
strong at the *physical/RF edge* of your network — the things Scapy on a laptop can't
touch:

| Layer | Best tool | What you learn |
|-------|-----------|----------------|
| Wi-Fi RF (APs, clients, deauth, handshakes) | **ESP32 + Marauder** on the Flipper | Which APs exist, weak/open/legacy encryption, deauth resilience, WPA handshakes |
| Sub-GHz remotes (garage, gate, some sensors) | **Flipper Sub-GHz** | Whether your remotes use static (replayable) vs rolling codes |
| Access cards / fobs / tags | **Flipper NFC & 125 kHz RFID** | Whether your badges are clonable, default keys, UID-only readers |
| Wired/IP traffic (ARP, DNS, scans, payloads) | **This Scapy toolkit** on a laptop | ARP spoofing exposure, DNS behavior, port exposure, plaintext payloads |

The Flipper finds the *doors*; Scapy inspects what goes *through* them once you're on
the wire. This guide runs both and connects them.

```
  ┌─────────────────────┐        ┌──────────────────────┐        ┌────────────────────┐
  │  Flipper + Marauder │  →     │  Your laptop on the  │  →     │  This Scapy toolkit │
  │  (RF / Wi-Fi recon) │  info  │  same test network   │  pcap  │  (analyze & detect) │
  └─────────────────────┘        └──────────────────────┘        └────────────────────┘
        find the AP,                get on the wire,                 prove the weakness,
        weak encryption,            capture traffic                  then design the fix
        replayable remotes
```

---

## 2. One-time setup checklist

**On the Flipper (Momentum firmware):**

- [ ] Momentum firmware installed and up to date (via qFlipper or the Momentum web
      updater). Momentum ships the Marauder companion app and generous Sub-GHz region
      settings.
- [ ] SD card seated and formatted; you'll store captures (`.cap`, `.sub`, `.nfc`) here.
- [ ] Set your **region** correctly in Momentum settings so Sub-GHz frequencies are legal
      where you are.

**On the ESP32 Wi-Fi Dev Board:**

- [ ] Board flashed with a current **Marauder** build (use the official
      `esp32-marauder` releases matching your board — the official Flipper Wi-Fi Dev
      Board, or a generic ESP32 like the Wemos/DevKit variants).
- [ ] Board seats on the Flipper GPIO header; launch **Apps → GPIO → [ESP32] Marauder**
      (Momentum groups it under GPIO/companion apps).
- [ ] Confirm the Flipper talks to it: the Marauder app should show a version banner, not
      a timeout.

**On your test laptop (for the Scapy side):**

- [ ] Python 3 + Scapy: `pip install -r requirements.txt` (or use `./run.sh`).
- [ ] A Wi-Fi adapter that supports **monitor mode** *if* you want to capture Wi-Fi on the
      laptop too (many built-in cards don't; a cheap external adapter with an Atheros or
      MediaTek chipset does). For wired analysis you don't need this.
- [ ] Run capture/spoof tools with `sudo` (raw sockets need root).

**Build a safe target — don't practice on your live home network first:**

- [ ] A **spare router** or a guest SSID you fully control, ideally on a separate VLAN.
- [ ] One or two throwaway client devices (an old phone, a Raspberry Pi).
- [ ] A spare RFID fob / NFC tag and, if you have one, a Sub-GHz remote you own.

This isolated setup means a stray deauth or ARP spoof can't knock your household offline.

---

## 3. The core loop

Everything below is the same four-step loop, whatever the technology:

1. **Recon (passive first).** List what's there without transmitting — APs, clients,
   remotes, cards. Passive scanning is lower-risk and teaches you the lay of the land.
2. **Capture.** Grab the artifact: a WPA handshake `.cap`, a Sub-GHz `.sub`, an NFC dump,
   or a pcap of wired traffic.
3. **Analyze.** Move the artifact to the laptop and inspect it — Scapy toolkit for pcaps,
   `aircrack-ng`/`hashcat` for handshakes, the Flipper UI for card/remote structure.
4. **Fix & re-test.** Change one thing (rotate a key, disable WPS, enable PMF, swap a
   static-code remote), then repeat the loop to confirm the weakness is gone.

The learning is in step 4. Anyone can capture; the skill is closing the gap and proving
it closed.

---

## 4. Track A — Wi-Fi (ESP32 + Marauder)

Marauder turns the ESP32 into a Wi-Fi recon/test radio driven from the Flipper screen.
Work these in order — passive to active.

### 4.1 Passive discovery (no transmit)
- **Scan AP** / **Scan AP (list)** — enumerate nearby access points: SSID, BSSID,
  channel, encryption, RSSI. Look at *your* SSID's row:
  - Encryption `OPEN` or `WEP` → immediate finding.
  - `WPA`/`WPA2-TKIP` (not CCMP/AES) → legacy, weak.
  - Note the **channel** — you'll target captures there.
- **Scan Stations** — see which clients are associated with which AP. This is your map of
  what's actually connected.
- **Sniff / packet monitor** — watch raw management traffic; good for understanding
  beacons, probe requests (which reveal device SSID history), and association frames.

**What "good" looks like:** WPA2-CCMP or WPA3, PMF (802.11w) enabled, WPS off, no clients
leaking a long probe-request history.

### 4.2 Handshake capture (still mostly passive)
- Select your test AP, run **Sniff PMKID / capture handshake**. To force a client to
  re-authenticate you *can* send a targeted deauth (active — see 4.3), but try the
  passive PMKID route first; it needs no deauth.
- Save the `.cap`/`.pcap` to SD.
- Move it to the laptop and crack **only against a wordlist you made for your own test
  passphrase** to measure strength:
  ```bash
  # convert + crack your OWN handshake to test passphrase strength
  hcxpcapngtool -o hash.hc22000 capture.pcap
  hashcat -m 22000 hash.hc22000 your_wordlist.txt
  ```
  If your real passphrase falls to a wordlist in minutes, that's the finding — lengthen
  it. If it survives, you've validated it.

### 4.3 Active tests (transmit — your network only)
- **Deauth (targeted)** — send deauth frames to *your* test client/AP pair and watch
  whether it drops. This measures **deauth resilience**:
  - Client drops instantly → PMF/802.11w is **off**. Turn it on in the router and re-test;
    a PMF-protected network should shrug off the deauth.
- **Beacon spam / probe flood / Evil-Portal** — Marauder can broadcast fake SSIDs or host
  a captive portal. Use these only to understand how *your own* clients react (do they
  auto-join an open SSID matching a known name?), never to lure others.

> The single most useful Wi-Fi lesson here: run a deauth against your network, confirm it
> works, enable **802.11w / PMF**, run it again, confirm it's now ineffective. That's a
> complete find→fix→verify loop in ten minutes.

---

## 5. Track B — the Flipper's own radios

No ESP32 needed for these — the Flipper's built-in radios cover the *physical* side of
your "network" (the doors, gates, badges, and remotes around it).

### 5.1 Sub-GHz (315/433/868/915 MHz remotes)
- **Read / Read RAW** on a remote you own (garage, gate, ceiling fan, some IoT sensors).
- **The lesson:** press the remote twice and capture twice.
  - Same signal both times, and a **replay** re-triggers the device → **static code**
    (weak; replayable). Common on cheap gate/garage remotes.
  - Signal changes each press and replay does nothing → **rolling code** (KeeLoq etc.) —
    good, working as designed.
- **Fix:** replace static-code openers with rolling-code units for anything protecting
  physical access.

### 5.2 NFC (13.56 MHz — access cards, some payment-era tags)
- **Read** your office/building fob or a hotel-style card you own.
  - **MIFARE Classic** with default keys (`FFFFFFFFFFFF`) → clonable; the card's keys were
    never changed. Finding.
  - **UID-only** systems (reader checks only the card serial) → trivially cloneable to a
    magic/UID-writable card. Finding.
  - **MIFARE DESFire / secured** → modern; reads are limited without keys. Good.
- **Never** clone a credential you aren't authorized to duplicate. Test with your own
  cards to learn which category your access control falls into, then report weak ones to
  whoever owns the system.

### 5.3 125 kHz RFID (EM4100, HID Prox, T5577 fobs)
- **Read** a legacy fob → these are almost always **UID-only, unencrypted**. If your
  building still uses 125 kHz prox, that's a known-weak technology; the finding is the
  technology choice itself.

### 5.4 Infrared, iButton, BadUSB
- **IR** — learn/replay remotes; useful for understanding "universal remote" attack
  surface on TVs/ACs, low security relevance to a data network.
- **iButton (1-Wire)** — same static-serial weakness as 125 kHz RFID if used for door
  access.
- **BadUSB** — the Flipper can act as a keyboard and type a scripted payload into an
  unlocked machine. The lesson for *your* network: it proves why **screen-lock policy and
  USB port control matter**. Write a harmless BadUSB script (open a terminal, echo a
  message) and run it against your own test machine to see how fast an unlocked endpoint
  is compromised — then verify your lock policy stops it.

---

## 6. Bridging to the Scapy toolkit

Once Flipper/Marauder recon tells you *where* to look, get your laptop onto the test
network and use this repo to inspect the traffic. All commands assume you're in the repo
root and running as root (raw sockets).

> Install once: `pip install -r requirements.txt` (or `./run.sh`). Replace `wlan0`/IPs
> with your test network's values.

### 6.1 See what's talking (passive monitor)
Marauder showed you the clients; now watch their IP traffic:
```bash
sudo python3 blue_team_toolkit.py --interface wlan0 --mode monitor
```
Lists `src -> dst | proto` for every IP packet — a quick map of who talks to whom.

### 6.2 Confirm exposed services (SYN scan a device you own)
Marauder found a suspicious IoT client? Check its open ports:
```bash
sudo python3 red_team_toolkit.py scan --target 192.168.50.42 --ports 22 23 80 443 8080 1883
```
Open **23 (telnet)** or **1883 (unauthenticated MQTT)** on an IoT device is a classic
finding. Cross-check with the blue-team scan *detector* to see it from the defender's
side:
```bash
sudo python3 blue_team_toolkit.py --interface wlan0 --mode scan   # flags >20 SYNs from one host
```

### 6.3 Prove the ARP-spoofing exposure (your test client only)
This is the wired analog of a Wi-Fi deauth — it shows whether a device will blindly trust
a forged gateway:
```bash
# Only against a device you own, on your isolated test LAN:
sudo python3 red_team_toolkit.py arp --target 192.168.50.42 --gateway 192.168.50.1 --iface wlan0
```
In a second terminal, run the watcher to see it from the blue side and learn the
detection signature:
```bash
sudo python3 blue_team_toolkit.py --interface wlan0 --mode arp
```
**Fix:** enable dynamic ARP inspection / client isolation on the router, or note the
device as untrustworthy on a shared segment. Stop the spoofer with `Ctrl-C` — it restores
the ARP tables on exit.

### 6.4 Look for plaintext / reverse-shell payloads
Capture some traffic to a pcap (with `tcpdump -i wlan0 -w test.pcap`), then:
```bash
python3 purple_team_toolkit.py --mode reverse --pcap test.pcap   # flags cmd.exe, /bin/bash, curl, etc.
python3 purple_team_toolkit.py --mode hybrid                     # live SYN / SYN-ACK tagging
python3 purple_team_toolkit.py --mode anomaly                    # per-IP packet-rate anomalies
```
The lesson: any credential or command you can *read* in the payload scanner is a service
running plaintext — move it to TLS.

> **Note:** `purple_team_toolkit.py` currently has its Python wrapped in Markdown code
> fences, and `run.sh` points at a `scapy_tool.py` that doesn't exist yet — see
> [§8](#8-turning-findings-into-fixes) for the small cleanups that make these runnable.
> Until then, run `red_team_toolkit.py` / `blue_team_toolkit.py` directly as shown above.

---

## 7. A first hands-on session

A concrete 60–90 minute run to build the muscle memory, all on your isolated test setup:

1. **(10 min) Map the air.** Marauder → *Scan AP* and *Scan Stations*. Write down your
   test AP's encryption, channel, and connected clients.
2. **(10 min) Baseline the wire.** Laptop on the test SSID →
   `blue_team_toolkit.py --mode monitor`. Watch the IP conversations for a couple minutes.
3. **(15 min) Deauth → PMF loop.** Marauder targeted deauth on your test client → confirm
   it drops → enable 802.11w/PMF on the router → deauth again → confirm it *doesn't* drop.
   **You just fixed and verified a real weakness.**
4. **(15 min) Handshake strength.** Capture your own WPA handshake/PMKID → crack against a
   short wordlist on the laptop. Weak passphrase? Lengthen it and re-capture.
5. **(10 min) Device exposure.** Pick one IoT client → `red_team_toolkit.py scan` its
   common ports → note anything plaintext (telnet/HTTP/MQTT).
6. **(10 min) Physical edge.** Read one Sub-GHz remote twice (static vs rolling) and one
   access fob (default keys vs secured).
7. **(10 min) Write it up.** Three columns: *what you found*, *the fix*, *did re-test
   confirm it*. That table is the whole point.

---

## 8. Turning findings into fixes

Two categories: fixes to **your network**, and small fixes to **this toolkit** so the
commands above actually run.

**Network fixes you'll likely land on:**
- Wi-Fi: WPA3 (or WPA2-CCMP minimum), **PMF/802.11w on**, WPS **off**, a long random
  passphrase, guest/IoT SSID on its own VLAN.
- Devices: close telnet/plaintext HTTP, put IoT on an isolated VLAN, change default creds.
- Physical: rolling-code remotes, secured (DESFire) badges instead of UID-only 125 kHz
  prox.
- Endpoints: enforced screen lock + USB control (defeats BadUSB).

**Toolkit cleanups worth doing (I can do these next if you want):**
- `purple_team_toolkit.py` — the code is wrapped in ```` ```python ```` Markdown fences,
  so it won't execute as-is; strip the fences. It also uses `UDP` in `dns_spoof` in the
  red toolkit without importing it.
- `run.sh` — points at `scapy_tool.py`, which doesn't exist. Either add a small unified
  `scapy_tool.py` dispatcher or repoint `run.sh` at the three existing toolkits.
- `red_team_toolkit.py` `dns_spoof()` references `UDP` but only imports it implicitly —
  add `UDP` to the Scapy import line.

Say the word and I'll fix those so `./run.sh` and all three toolkits run clean.

---

## 9. Legal & safety notes

- **Only your own or explicitly authorized systems.** Wi-Fi deauth and RF replay against
  others is illegal in most jurisdictions, full stop.
- **Sub-GHz transmit is regulated.** Set your Momentum region; don't transmit on bands or
  power levels you're not licensed for.
- **Don't clone credentials you aren't authorized to duplicate**, even to "test" — reading
  to categorize is one thing, writing a working clone of someone else's badge is another.
- **Isolate first.** Practice on a spare router/VLAN so a mistake can't disrupt others.
- **Keep records.** A one-line log of what you tested, when, and your authorization for it
  protects you.

---

## 10. Glossary & further reading

- **Momentum** — custom Flipper Zero firmware (fork lineage: Xtreme/Unleashed family) with
  broad Sub-GHz support and the Marauder companion integration.
- **Marauder** — ESP32 Wi-Fi security firmware; provides AP/station scanning, sniffing,
  deauth, beacon/probe tools, and Evil-Portal.
- **PMF / 802.11w** — Protected Management Frames; makes deauth/disassoc frames
  authenticated, defeating basic deauth attacks. The one setting most worth learning.
- **PMKID** — a value in the first handshake message that can sometimes yield the WPA
  passphrase without deauthing a client.
- **Static vs rolling code** — replayable fixed Sub-GHz signal vs one that changes every
  press (KeeLoq). The core Sub-GHz security distinction.
- **UID-only reader** — an access system that trusts only a card's serial number; trivially
  cloneable.

Official docs to keep handy: Flipper Zero docs (`docs.flipper.net`), the Momentum firmware
project, and the `esp32-marauder` project's wiki. Prefer the official release channels for
firmware — third-party builds are a supply-chain risk on a device that touches your keys
and cards.
