---
name: "alibaba-live-kms-key-mutation-guard"
description: "Gate KMS key deletion and disable operations. All data encrypted with a deleted CMK (OSS SSE-KMS, ECS encrypted disks, RDS/PolarDB TDE) becomes permanently and irrecoverably inaccessible. This guard e"
category: cloud-security
subcategory: cloud-security
tags: ["type:audit"]
relevance: 1
source: "https://github.com/Raishin/vanguard-frontier-agentic/blob/HEAD/skills/alibaba/alibaba-live-kms-key-mutation-guard/SKILL.md"
author: "Raishin"
license: "Apache-2.0"
---
# alibaba-live-kms-key-mutation-guard


## Description
Gate KMS key deletion and disable operations. All data encrypted with a deleted CMK (OSS SSE-KMS, ECS encrypted disks, RDS/PolarDB TDE) becomes permanently and irrecoverably inaccessible. This guard enforces complete CMK dependency audits, deletion window confirmation, and explicit operator approval before any key state mutation.


## Tags
type:audit


## Source
https://github.com/Raishin/vanguard-frontier-agentic/blob/HEAD/skills/alibaba/alibaba-live-kms-key-mutation-guard/SKILL.md


## Relevance Score
1
