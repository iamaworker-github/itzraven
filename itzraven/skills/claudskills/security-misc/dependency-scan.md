---
name: "dependency-scan"
description: "Scan project dependencies for known vulnerabilities (CVEs), auto-fix safe patches, and generate SBOM. Auto-detects all package managers in monorepos — npm (npm audit), yarn (yarn audit), pnpm (pnpm au"
category: security
subcategory: security-misc
tags: ["lang:javascript", "lang:java", "type:audit"]
relevance: 1
source: ""
author: ""
license: ""
---
# dependency-scan


## Description
Scan project dependencies for known vulnerabilities (CVEs), auto-fix safe patches, and generate SBOM. Auto-detects all package managers in monorepos — npm (npm audit), yarn (yarn audit), pnpm (pnpm audit), pip/poetry (pip-audit), Cargo (cargo audit), Go modules (govulncheck), Maven (dependency-check), Gradle, Bundler (bundle audit), and Composer. Categorizes findings by severity (Critical/High/Medium/Low), dependency type (direct vs transitive), and fix availability. Applies safe patch-level fixes automatically, adds npm overrides or yarn resolutions for transitive vulnerabilities, flags major version bumps for manual review, and generates CycloneDX SBOM with license compliance checks (GPL, AGPL, LGPL flagging). Verifies fixes by re-scanning and running tests before committing.


## Tags
lang:javascript, lang:java, type:audit


## Relevance Score
1
