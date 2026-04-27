# wifireap

Enumerates wireless network information from the local Linux system. Collects active interface details, detects nearby APs using deprecated or weak encryption (WEP/TKIP) and WPS, and harvests saved pre-shared keys (PSKs) from NetworkManager profiles and `wpa_supplicant.conf`.

## What It Does

Runs in three phases:

**1. Basic interface enumeration** — runs `ip link`, `iwconfig` (falls back to `iw dev` if not installed), and `nmcli device status` to show all network interfaces and their current state.

**2. Weak AP detection** — scans visible access points and flags:
- `[WEP]` — network has the `Privacy` capability bit set but no RSN or WPA information elements, indicating WEP-only encryption
- `[TKIP]` — network advertises TKIP as its group or pairwise cipher (WPA1 / mixed-mode WPA2, susceptible to TKIP-based attacks)
- `[WPS]` — network broadcasts a WPS information element (Wi-Fi Protected Setup), enabling PIN-brute-force attacks (Reaver/Bully)

**3. Saved credential harvesting** — reads plaintext PSKs and passwords from:
- `/etc/NetworkManager/system-connections/*.nmconnection` — NetworkManager stores PSKs here in cleartext, readable by root
- `/etc/wpa_supplicant/wpa_supplicant.conf` — wpa_supplicant config frequently contains `psk=` entries in plaintext

## Detection Logic

### WEP
A network is classified as WEP when its `iw scan` entry shows the `Privacy` capability flag but contains no `RSN:` or `WPA:` information element blocks. Modern WPA2/WPA3 networks always include an RSN IE even when the Privacy bit is set.

```
capability: ESS Privacy (0x0011)   ← Privacy set, no RSN/WPA block = WEP
```

### TKIP
Flagged when `iw scan` output contains either of:
```
Group cipher: TKIP
Pairwise ciphers: TKIP
```
TKIP as the group cipher is common in "WPA2 mixed mode" deployments and is vulnerable to the TKIP MIC attack.

### WPS
Flagged when `iw scan` output contains a `WPS:` vendor IE block:
```
WPS:
     * Version: 1.0
     * Wi-Fi Protected Setup State: 2 (Configured)
```

## Scan Fallback

`iw dev <iface> scan` requires root and fails when NetworkManager holds an exclusive lock on the interface. In that case the tool automatically falls back to:

```bash
nmcli -t -f BSSID,SSID,SECURITY dev wifi list
```

nmcli reports security type in its `SECURITY` column without requiring raw scan access, and flags `WEP` and `WPA1` entries directly.

## Build

**Standalone:**
```bash
g++ wirelessinfo.cpp -o wirelessinfo -std=c++20
```

**As part of the main ShadowHarvester build:**
```bash
make
```

## API

When integrated into the main binary, functions are exported via `wirelessinfo.h`:

| Function | Description |
|---|---|
| `wifiScan()` | Runs basic interface enumeration commands, returns raw output lines |
| `runWirelessInfo()` | Runs all three phases (enumeration, weak AP scan, PSK harvest) and returns combined results |

## Example Output

```
[WEP]  BSSID: AA:BB:CC:DD:EE:FF  SSID: OldOfficeWifi
[TKIP] BSSID: 11:22:33:44:55:66  SSID: HomeNetwork_2G
[WPS]  BSSID: 77:88:99:AA:BB:CC  SSID: NETGEAR42

[NetworkManager PSKs]
psk=SuperSecretPassword123

[wpa_supplicant.conf]
network={
    ssid="CorpWifi"
    psk="AnotherPassword"
}
```

## Notes

- `iw dev <iface> scan` requires root — run as root for full AP scan coverage
- NetworkManager connection files under `/etc/NetworkManager/system-connections/` are root-readable by default; post-exploitation access makes them trivially readable
- PSKs found in `wpa_supplicant.conf` are often reused across other systems and services
- WPS-enabled APs can be attacked offline with Pixie Dust (if the AP is vulnerable) or online with Reaver even without knowing the PSK
- TKIP-based networks are vulnerable to the Beck-Tews attack and chopchop-style decryption
