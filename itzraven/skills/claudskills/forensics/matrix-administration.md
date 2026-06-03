---
name: "matrix-administration"
description: "Use when administering a Synapse / Matrix homeserver — list or snapshot all rooms, rate room health (public, unencrypted, orphaned), render a Graphviz map of the room/space tree, force-join users, pro"
category: forensics
subcategory: forensics
tags: ["type:audit"]
relevance: 1
source: "https://github.com/netresearch/matrix-skill"
author: "netresearch"
license: ""
---
# matrix-administration


## Description
Use when administering a Synapse / Matrix homeserver — list or snapshot all rooms, rate room health (public, unencrypted, orphaned), render a Graphviz map of the room/space tree, force-join users, promote room admins, harden rooms (add-to-space + restrict + encrypt), deactivate Matrix users (with GDPR erase), find biggest rooms by DB size, audit where a user is admin or member, replay join/leave timelines, or search unencrypted history. Trigger on any '/_synapse/admin', server-wide room operation, Matrix user offboarding, or anything requiring a homeserver-admin token — even without 'admin API' in the prompt. Companion to matrix-communication.


## Tags
type:audit


## Source
https://github.com/netresearch/matrix-skill


## Relevance Score
1
