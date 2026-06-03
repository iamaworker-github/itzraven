---
name: Advanced Insecure Deserialization
category: web-security
description: Multi-language deserialization attacks — Node.js, Golang, Rust, Ruby, container, message queue, serverless vectors
tags: [deserialization, gadget-chain, php, java, nodejs, golang, rust, ruby]
---

## Advanced Insecure Deserialization

### PHP
- `unserialize()` with magic methods: `__wakeup()`, `__destruct()`, `__toString()`
- Phar deserialization: `phar://wrapper` triggers deserialization on any file function
- PHPGGC gadget chains for popular frameworks (Symfony, Laravel, WordPress)
- Session deserialization via php_serialize handler
- SSRF via Phar deserialization

### Java
- `ObjectInputStream.readObject()` with CommonsCollections chains
- ysoserial gadget chains (CommonsCollections 1-12, Jdk7u21, JRMPClient)
- FastJSON auto-type deserialization RCE
- Jackson polymorphic type handling (enableDefaultTyping)
- XStream deserialization (CVE-2021-21344-21351)
- SnakeYAML constructor injection via !!javax.script.ScriptEngineManager

### Node.js
- `_$$ND_FUNC$$_` IIFE pattern in `node-serialize`
- `serialize-javascript` function serialization abuse
- `funcster` sandbox escape
- `eval()` via `vm.runInNewContext` sandbox bypass
- Socket.IO / Engine.IO JSON parser deserialization

### Golang
- `encoding/gob` type confusion via register mismatch
- `msgpack` unsafe reflection interface{}
- `protobuf` `any` field type confusion
- `yaml.v2` `!interface{}` type confusion
- `json.RawMessage` with `interface{}` overloads

### Rust
- `serde` deserialization with `serde_json::from_str` on untrusted input
- `bincode` type confusion via #[serde(untagged)] enums
- `ron` (Rusty Object Notation) with arbitrary type instantiation
- YAML deserialization leading to heap overflow

### Ruby
- `Marshal.load()` with gadget chains
- `YAML.load()` with `!ruby/object:` syntax
- `Gem::Requirement` gadget chain
- `ERB` template rendering in YAML
- `ActiveSupport::Deprecation::DeprecatedInstanceVariableProxy`

### Container / Kubernetes Vectors
- ConfigMap deserialization in custom controllers
- Admission Webhooks processing malformed objects
- CRD (Custom Resource Definition) controller deserialization
- Sidecar injector message parsing

### Message Queue Vectors
- Kafka deserialization in consumer group rebalance
- RabbitMQ message body type confusion
- Redis pub/sub message deserialization
- NATS message envelope type confusion

### Serverless Functions
- AWS Lambda event JSON deserialization
- Google Cloud Functions HTTP trigger body
- Azure Functions input binding deserialization
- Cloudflare Workers `request.json()` parsing

### Detection and Prevention
- Signed serialization blobs (HMAC verification)
- Allow-list class resolution
- Type whitelisting per endpoint
- Deserialization audit logging
- Memory/CPU limits on deserialization
- Use of safe alternatives (JSON, MessagePack typed)
