---
name: Wireless Security Testing
category: wireless
description: Wi-Fi 6/6E/7 security, WPA2/3 attacks, FragAttacks, NAC bypass, sideband attacks (BLE/Zigbee/Z-Wave/LoRa), WIDS evasion
tags: [wireless, wifi, bluetooth, zigbee, z-wave, lora, wpa3, fragattacks]
---

## Wireless Security Testing

### Wi-Fi Recon
- Adapter: select chipset with monitor mode + packet injection (Atheros AR9271, RTL8812AU)
- Monitor mode: `ip link set wlan0 down && iw dev wlan0 set type monitor`
- Multi-band scanning: `airodump-ng wlan0` (2.4GHz, 5GHz, 6GHz)
- WPS detection: `wash -i wlan0`

### WPA2-PSK Attacks
- 4-way handshake capture: `airodump-ng -c <channel> --bssid <MAC> -w capture wlan0`
- PMKID capture: `hcxdumptool -o capture.pcapng -i wlan0`
- Cracking: `hashcat -m 22000 capture.hccapx wordlist.txt`
- Dictionary + rules: best strategy (rockyou + best64.rule)

### WPA3-SAE Attacks
- Transition mode downgrade (WPA3 AP with WPA2 fallback)
- Dragonblood: CVE-2019-9494 (group downgrade), CVE-2019-9495 (side-channel)
- SAE side-channel via timing attack (CVE-2019-13377)
- Detection: check beacon RSNE for SAE + PSK simultaneous support

### WPA-Enterprise (802.1X/EAP)
- PEAP/MSCHAPv2: hostile twin attack with eaphammer
- EAP-TLS: certificate validation bypass
- EAP-PWD: dictionary attack on password element
- RADIUS: shared secret brute-force
- AD credential extraction via cracked PEAP-MSCHAPv2

### WPS Attacks
- Pixie Dust: offline PIN recovery (PixieWPS)
- Online brute-force: `reaver -i wlan0 -b <MAC> -vv`
- Vendor PIN generators: known PIN patterns per model

### Evil Twin Attacks
- KARMA attack: respond to any probe request
- MANA: advanced KARMA + known network list mining
- Captive portal: `airgeddon` or `fluxion`
- Post-association MITM: dnsspoof, sslstrip, bettercap

### KRACK / FragAttacks
- KRACK (CVE-2017-13077-13088): 4-way handshake key reinstallation
- FragAttacks (CVE-2020-24586-24588): frame aggregation + fragmentation
- Testing: use `krackattacks-scripts` with wpa_supplicant

### Deauth / Disassociation
- Targeted: `aireplay-ng -0 5 -a <AP> -c <client> wlan0`
- Broadcast: `aireplay-ng -0 5 -a <AP> wlan0` (hits all clients)
- PMF-aware: 802.11w management frame protection bypass

### MAC Randomization Defeat
- Per-SSID probe request clustering via sequence numbers
- Frame timing fingerprinting
- Information element ordering analysis

### NAC / 802.1X Bypass
- Transparent bridge through authenticated host (silentbridge)
- DHCP starvation + rogue DHCP server
- ARP spoofing on wired segments

### Sidebands / Adjacent Wireless
- BLE: redfang, crackle, btproxy for pairing attacks
- Zigbee: KillerBee, apimote, zbstumbler
- Z-Wave: Z-Force, EZ-Wave, S0 key reuse
- LoRaWAN: LoRaPWN, ChirpStack, ABP key reuse
- Sub-GHz: rtl_433, HackRF, YardStick One (433/868/915 MHz)

### WIDS Evasion
| Attack | Detection | Evasion |
|--------|-----------|---------|
| Deauth | Valid reason code check | Use reason code 7 (class 3 frame from nonassociated STA) |
| Rogue AP | SSID beacon match | Clone legitimate SSID + slightly different BSSID |
| KARMA | Unique probe response | Rate-limit probe responses |
| WPS lockout | Too many WPS NACKs | Vendor-specific timing delays |
