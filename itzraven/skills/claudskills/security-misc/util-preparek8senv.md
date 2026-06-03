---
name: "util-preparek8senv"
description: "Prepare Kubernetes environment infrastructure by generating K8s manifests for all 3rd party supporting applications for a single target environment defined in CLAUDE.md. Creates/updates ENVIRONMENT.md"
category: security
subcategory: security-misc
tags: ["tool:k8s"]
relevance: 0
source: ""
author: ""
license: ""
---
# util-preparek8senv


## Description
Prepare Kubernetes environment infrastructure by generating K8s manifests for all 3rd party supporting applications for a single target environment defined in CLAUDE.md. Creates/updates ENVIRONMENT.md with per-environment configs and credentials, then generates persistent StatefulSet-based K8s manifests for each 3rd party application (databases, message queues, caches, SSO, API gateways, etc.) directly in the `environment/` folder. Since the `environment/` folder is gitignored, each machine maintains its own independent copy. Ensures all services are remotely accessible using tools from DEVTOOL.md. Trigger on keywords: "prepare k8s environment", "prepare kubernetes", "setup k8s infra", "generate k8s manifests for 3rd party", "prepare environment", "setup infrastructure", "prepare k8s", "init k8s environment", "scaffold k8s environment". Accepts an optional environment argument to select which Kubernetes environment to generate for.


## Tags
tool:k8s


## Relevance Score
0
