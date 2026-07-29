# Attack Detection Package — Design Spec

## Overview

A pure Go attack detection library providing a unified interface + registry pattern, covering **32 detectors** across **5 categories**. **Implementation complete (2026-07-29).**

## Package Structure

```
security-go/
├── go.mod
├── security.go              # Result, Severity, Detector interface, Engine
├── all/all.go               # RegisterAll — registers all built-in detectors
├── injection/               # Injection attacks (10)
├── protocol/                # Protocol & request attacks (9)
├── httpval/                 # HTTP protocol validation (5)
├── data/                    # Data & serialization attacks (5)
├── file/                    # File & sensitive data (3)
└── storage/                 # Pluggable storage backends
    ├── storage.go           # Backend interface
    ├── memory.go            # In-memory (with TTL cleanup)
    ├── file.go              # JSON file persistence
    └── redis/               # Redis sub-module (optional dependency)
```

## Core API

- `Result` — Name, Detected, Message, Severity, Details
- `Detector` interface — `Name() string`, `Detect(input string) *Result`
- `Engine` — registry + `Detect()` / `DetectAll()` / `DetectRequest(*http.Request)`
- All detectors use pre-compiled regex patterns

## Storage Backend Interface

```go
type Backend interface {
    Incr(key string, window time.Duration) (int, error)
    Get(key string) (int, error)
    Block(key string, duration time.Duration) error
    IsBlocked(key string) (bool, error)
    Close() error
}
```

Implementations: Memory (sync.Mutex + map + reap goroutine), File (JSON persistence), Redis (go-redis/v9 sub-module).

## Detectors

| Category | Name | Key Patterns |
|----------|------|-------------|
| injection | xss | `<script>`, `on[a-z]+=`, `javascript:`, SVG/CSS vectors |
| injection | sql | UNION SELECT, `/**/`, sleep/benchmark, boolean blind, schema enum |
| injection | command | backtick, `$()`, pipe, `/dev/tcp`, PHP exec functions |
| injection | nosql | MongoDB `$ne`/`$gt`/`$regex`/`$where`, auth bypass |
| injection | ldap | filter operators `(`, `)`, `&`, `|`, `*` |
| injection | xpath | boolean bypass `1=1`, `' or '1'='1` |
| injection | jndi | `${jndi:ldap://`, `${lower:j}`, `${env:}` |
| injection | ssi | `<!--#exec`, `<!--#include`, `<!--#echo` |
| injection | graphql | `__schema`, `__type`, deep nested query, mutation detect |
| injection | ssti | Jinja2 `{{}}`, FreeMarker `${}`, ERB `<% %>`, Python MRO |
| protocol | ssrf | internal IP, 169.254.169.254, IPv6 loopback, gopher/dict |
| protocol | xxe | `<!ENTITY`, parameter entities, DOCTYPE |
| protocol | header_injection | CRLF `%0d%0a`, Set-Cookie/Location injection |
| protocol | host_header | CRLF Host injection, X-Forwarded-Host poisoning |
| protocol | request_smuggling | TE/CL mismatch, dual TE, folded header |
| protocol | open_redirect | `//evil.com`, `javascript:`, `data:` |
| protocol | cors | Origin: null, ACA* header injection |
| protocol | websocket | Upgrade injection, null Origin, ws:// |
| protocol | dns_rebinding | Host header internal IP, localhost, hostname without TLD |
| httpval | method | Whitelist GET/POST/PUT/DELETE/HEAD/OPTIONS/PATCH |
| httpval | body_size | Max size check (default 10MB) |
| httpval | content_type | MIME whitelist (empty list = deny-all) |
| httpval | csrf_origin | Cross-origin Origin vs Host match |
| httpval | ip_blacklist | Window-based rate limit → auto ban (5/60s → 15min) |
| data | deserialization | PHP `O:digit:`, `C:digit:`, unserialize() |
| data | csv_injection | `=`, `@`, `+`, `-` formula prefix |
| data | mail_header | Bcc/Cc/From/To injection, MIME |
| data | jwt_attack | alg:none, kid path traversal, empty signature |
| data | prototype_pollution | `__proto__`, `constructor`, `__defineGetter__` |
| file | path_traversal | `../`, `..\\`, php://filter, null byte |
| file | upload | Extension whitelist + PHP tag content scan |
| file | data_leak | Credit card, AWS key, private key, connection string, JWT secret |

## Non-Goals

- No HTTP middleware (pure detection library)
- No real-time request interception (caller invokes detection)
- No attack blocking (detection only; ip_blacklist provides block-listing support)

## Implementation Status (2026-07-29)

- **All 32 detectors implemented** — entry point: `all.RegisterAll(engine)`
- **Test coverage** — 7/8 packages tested (`all` pending), httpval gained 32 tests
- **Code review complete** — 3 bugs fixed (see review report), `go vet` zero warnings
- **Known limitations** — `storage/redis/` sub-module needs `go mod tidy`; protocol package receiver style pending unification

---

Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
