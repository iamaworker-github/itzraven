---
name: "capabilities-detect"
description: "Detect installed security binaries (nuclei, snort, yara, semgrep, syft, grype, trivy, cosign, gh, package managers) and repo signals (manifests, Dockerfiles, IaC, CI configs); write .vulnetix/capabili"
category: network-security
subcategory: network-security
tags: ["tool:docker"]
relevance: 2
source: "https://github.com/Vulnetix/pix-ai-coding-assistant/blob/HEAD/vulnetix/skills/capabilities-detect/SKILL.md"
author: "Vulnetix"
license: "Apache-2.0"
---
# capabilities-detect


## Description
Detect installed security binaries (nuclei, snort, yara, semgrep, syft, grype, trivy, cosign, gh, package managers) and repo signals (manifests, Dockerfiles, IaC, CI configs); write .vulnetix/capabilities.yaml. Use when starting a session, after installing a new tool (brew install yara), when other Pix skills emit "unknown capability" notes, or to force-refresh stale capability state.


## Tags
tool:docker


## Source
https://github.com/Vulnetix/pix-ai-coding-assistant/blob/HEAD/vulnetix/skills/capabilities-detect/SKILL.md


## Relevance Score
2
