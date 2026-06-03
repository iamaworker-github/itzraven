---
name: "acko-deploy"
description: "MUST USE for deploying Aerospike on Kubernetes. Contains CE-specific YAML templates, validated AerospikeCluster CR examples, and critical constraints that prevent enterprise-only config mistakes (feat"
category: security
subcategory: security-misc
tags: ["tool:k8s"]
relevance: 0
source: ""
author: ""
license: ""
---
# acko-deploy


## Description
MUST USE for deploying Aerospike on Kubernetes. Contains CE-specific YAML templates, validated AerospikeCluster CR examples, and critical constraints that prevent enterprise-only config mistakes (feature-key-file, security sections crash CE pods). Without this skill, deployments fail on first attempt due to CE 8.1 breaking changes (data-size not memory-size, no info port 3003) or webhook map/list shape rules (service/network must be maps; logging must be a list). Triggers on: deploy/create/set up Aerospike on K8s, kind, minikube, EKS, GKE; AerospikeCluster CR; ACKO operator; spec.operations / WarmRestart / PodRestart YAML; NoSQL database on Kubernetes. 9 ready-to-use YAML examples from minimal single-node to full-featured multi-rack.


## Tags
tool:k8s


## Relevance Score
0
