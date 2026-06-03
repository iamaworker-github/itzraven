---
name: "palo-alto"
description: "PAN-OS firewall'unda DNAT (port yönlendirme) ve security policy source kısıtlama işlerini doğal dilden uygular. Müşteri tek cümlede ister ('198.51.100.108'in 80 portu 192.168.1.50:90'a yönlendirilsin'"
category: network-security
subcategory: network-security
tags: []
relevance: 1
source: "https://github.com/AhmetBSD/ai/blob/bc711bbe8ef43687470fe6309886f465ce707448/skills/palo-alto/SKILL.md"
author: "AhmetBSD"
license: "MIT"
---
# palo-alto


## Description
PAN-OS firewall'unda DNAT (port yönlendirme) ve security policy source kısıtlama işlerini doğal dilden uygular. Müşteri tek cümlede ister ("198.51.100.108'in 80 portu 192.168.1.50:90'a yönlendirilsin" / "RULE_108 sadece şu IP'lere açık olsun"); skill firewall'a doğrudan bağlanır, çakışmaları kontrol eder, idempotent şekilde NAT + security policy + service/address objelerini oluşturur ve commit eder. Credential'lar sadece process içinde tutulur, diske yazılmaz. Her çağrı öncesi auto-update yapar (24h cache).


## Source
https://github.com/AhmetBSD/ai/blob/bc711bbe8ef43687470fe6309886f465ce707448/skills/palo-alto/SKILL.md


## Relevance Score
1
