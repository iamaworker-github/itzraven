---
name: Cryptocurrency and Advanced OSINT Methodology
category: osint
description: Cryptocurrency investigation, layer 2 analysis, threat actor attribution, video/image OSINT, Bluesky/Mastodon analysis
tags: [osint, crypto, blockchain, threat-intel, attribution, video-analysis]
---

## Cryptocurrency OSINT

### Transaction Analysis
- Cielo: real-time wallet tracking
- TRM Labs: risk scoring, mixer detection
- Arkham Intelligence: entity labeling
- MetaSleuth: cross-chain tracing
- Chainalysis: professional investigation (Reactor)
- Elliptic Lens: illicit finance detection

### Layer 2 / Rollup Analysis
- zkSync, Arbitrum, Optimism, StarkNet
- Base, Blast, Scroll L2 ecosystems
- Bridge transactions: L1 → L2 deposit tracking
- MEV/sandwich false trails in analysis
- Privacy protocols on L2: Aztec, Railgun, Privacy Pools

### Wallet Profiling
- First transaction analysis (funding source)
- Exchange deposit/withdrawal patterns
- NFT flipper vs HODL identification
- DeFi protocol interaction patterns
- Cross-chain bridging behavior

## Threat Actor Attribution

### Actor-Centric Workflow
1. Scoping: define threat actor group, TTPs
2. Indicator harvesting: domains, IPs, wallets, emails
3. Infrastructure mapping: hosting, certs, DNS
4. Artifact profiling: malware, C2, phishing kits
5. Link analysis: shared infrastructure across campaigns

### Attribution Discipline
- Rule of three: require 3+ independent signals
- Strong signals: TTPs, exclusive infrastructure, code similarity
- Weak signals: language, timezone, naming conventions
- Confidence levels: Low (1-2 weak), Medium (1 strong), High (3+ strong)

### Russia-Specific Pivots
- EGRUL/EGRIP business registry
- zakupki.gov.ru government procurement
- hh.ru employee search
- RU WHOIS (not .ru TLD), RKN data
- Telegram channel analysis, VK API enumeration

### China-Specific Pivots
- gsxt.gov.cn business registry
- Tianyancha / Qichacha company research
- ICP filing lookup (beian)
- CNNIC domain registration data
- Weibo, WeChat, Douyin enumeration

## Video / Image OSINT

### Bluesky AT Protocol
- DID resolution via PLC directory
- Firesky real-time firehose monitoring
- PDS (Personal Data Server) data mining
- Following/follower graph analysis

### Mastodon / Fediverse
- WebFinger for user discovery
- FediSearch for content search
- Instance enumeration and federation analysis
- ActivityPub JSON-LD metadata extraction

### Chromolocation
- SunCalc: shadow length and direction analysis
- ShadeMap: shadow simulation from 3D city models
- Google Earth Pro historical imagery comparison
- Sentinel Hub EO Browser satellite imagery

### Synthetic Media Verification
- Sensity AI: deepfake detection
- Hive Moderation: AI-generated content
- Reality Defender: multi-modal deepfake detection
- C2PA provenance verification
- EXIF/metadata analysis and geolocation
