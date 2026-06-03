---
name: IoT/Embedded Device Security Testing
category: iot
description: Hardware reconnaissance, firmware analysis, UART/JTAG, RTOS, ICS/OT protocols (Modbus, BACnet, S7), MQTT/CoAP security testing
tags: [iot, embedded, firmware, hardware, rtos, modbus, mqtt, ics, scada]
---

## IoT / Embedded Security Testing

### Hardware Reconnaissance
- PCB inspection: look for debug headers, test points, JTAG/SWD
- SoC identification: read chip markings, search datasheets
- Debug header discovery: UART (3.3V TX/RX/GND), JTAG (TMS/TCK/TDI/TDO)
- Tools: multimeter, logic analyzer, Bus Pirate, J-Link, CH341A

### Flash Dumping
- SPI NOR: in-circuit dump with flashrom via clip
- eMMC: desolder and read with SD card adapter
- NAND: handle ECC, use hardware flasher
- OTA: capture firmware update via MITM proxy
- U-Boot: interrupt boot, `tftp` dump from memory

### Firmware Analysis
- Extract: `binwalk -Me firmware.bin`
- Filesystem: mount SquashFS/JFFS2/UBIFS
- Secrets: `grep -r "password\|secret\|key\|token" ./extracted/`
- Hardcoded credentials in config files, scripts, binaries
- CGI auditing: Boa, GoAhead, mini_httpd common CVEs
- Web interface: check for default credentials, command injection

### Bootloader Attacks
- U-Boot: interrupt countdown, `setenv bootargs init=/bin/sh`
- Secure boot bypass: downgrade attack, rollback to unsigned
- Key extraction from NVM/OTP via fault injection
- SPI flash desolder + external programmer

### RTOS Targets
- FreeRTOS: task list enumeration, heap overflow
- Zephyr: kernel configuration review, stack overflow
- ThreadX: bytecode verification bypass
- MicroEJ / Mbed OS: sandbox escape
- ESP-IDF: OTA update validation, partition table
- QNX: process manager, IPC vulnerabilities

### MCU Reverse Engineering
- SWD/JTAG with OpenOCD: `openocd -f interface/jlink.cfg -f target/stm32f4x.cfg`
- SAM-BA for Microchip SoCs
- Ghidra / Binary Ninja for firmware binary analysis

### Wireless Protocols
- BLE: bettercap, gatttool, pairing downgrade, MITM
- Zigbee/Thread/Matter: KillerBee, Touchlink abuse, zbdump
- Z-Wave: S0 key reuse attack (nonce reuse)
- LoRaWAN: ABP key reuse, join-request replay
- Sub-GHz: rtl_433, HackRF replay for garage doors, sensors

### ICS/OT Protocols
- Modbus: function code scanning (read coils, read registers)
- BACnet: device discovery, point enumeration
- OPC-UA: anonymous authentication, endpoint enumeration
- S7 (Siemens): S7comm PLC stop/start, block upload
- DNP3: unsolicited messages, object variation manipulation
- MQTT/CoAP: anonymous subscribe #, topic ACL bypass

### Companion Mobile App / Cloud API
- APK decompilation: `jadx`, `apktool`
- SSL pinning bypass: Frida, Objection
- Device claim by serial number
- IDOR on device management endpoints
- RTSP/WebRTC token abuse for camera access
- MQTT cloud bridge with weak auth

### Pivoting Across Devices
- Mesh protocol bridge attacks
- BLE central role swap in mesh
- Zigbee coordinator compromise
- Cloud account → device access → lateral movement
