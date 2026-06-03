---
name: "go-conventions"
description: "Apply Go project conventions — Go 1.25.x toolchain pinned via toolchain directive and GOTOOLCHAIN=local, vendored deps via go mod vendor, golangci-lint v2 strict (~50 enabled linters), gofmt + goimpor"
category: appsec
subcategory: appsec-tools
tags: ["lang:go"]
relevance: 0
source: ""
author: ""
license: ""
---
# go-conventions


## Description
Apply Go project conventions — Go 1.25.x toolchain pinned via toolchain directive and GOTOOLCHAIN=local, vendored deps via go mod vendor, golangci-lint v2 strict (~50 enabled linters), gofmt + goimports, gosec + semgrep + govulncheck + CodeQL static analysis, race-detector + fuzz-capable testing, reproducible-build flags (-trimpath, -buildid=) for TEE-attested binaries, cmd/ + internal/ + pkg/ layout, stdlib-first dependencies (log/slog, net/http, google/uuid, google.golang.org/protobuf). Use when starting a Go project, writing or reviewing Go code, configuring Go tooling, doing TEE-attested or reproducible builds, or evaluating compliance with these defaults. Co-activates with running-tdd-cycles, reviewing-changes, and engineering-philosophy.


## Tags
lang:go


## Relevance Score
0
