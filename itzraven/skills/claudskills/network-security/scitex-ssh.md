---
name: "scitex-ssh"
description: "Persistent, auto-reconnecting SSH reverse tunnels for NAT traversal — installs an `autossh` systemd unit on the local host so a bastion/relay server can SSH back in even through firewalls and dynamic "
category: network-security
subcategory: network-security
tags: ["lang:python"]
relevance: 0
source: ""
author: ""
license: ""
---
# scitex-ssh


## Description
Persistent, auto-reconnecting SSH reverse tunnels for NAT traversal — installs an `autossh` systemd unit on the local host so a bastion/relay server can SSH back in even through firewalls and dynamic IPs. Python API — `setup(port, bastion_server=, secret_key_path=)`, `remove(port)`, `status(port=None)`, `get_version()`. Defaults read from env vars `SCITEX_SSH_BASTION_SERVER` and `SCITEX_SSH_SECRET_KEY_PATH`. 3 MCP tools — `tunnel_setup`, `tunnel_remove`, `tunnel_status`. Bundled bash scripts (`setup-autossh-service.sh` / `remove-autossh-service.sh`) install/remove `autossh-tunnel-<port>.service` via systemctl. Drop-in replacement for hand-writing `autossh -M 0 -NR port:localhost:22 user@host` commands, crafting `/etc/systemd/system/autossh-tunnel-*.service` unit files by hand, `sshuttle`, and manual `ssh -R` plus `tmux` reconnect loops. Use whenever the user asks to "set up a reverse SSH tunnel", "keep SSH alive through NAT", "access a lab machine from outside", "tunnel through a bastion", "autossh systemd service", "check tunnel status", "remove a tunnel", "expose this machine via a jump host", or mentions bastion server, NAT traversal, autossh, reverse SSH, HPC login node.


## Tags
lang:python


## Relevance Score
0
