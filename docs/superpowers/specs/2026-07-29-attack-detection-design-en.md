# Attack Detection Package — Design Spec

## Overview

A pure Go attack detection library providing a unified interface + registry pattern, covering **36 detectors** across **6 categories**. **Implementation complete (2026-07-29); the `session` package was added on 2026-09-15.**

## Package Structure

```
security-go/
├── go.mod
├── security.go              # Result, Severity, Detector interface, Engine
├── all/all.go               # RegisterAll — registers all built-in detectors
├── injection/               # Injection attacks (10)
├── protocol/                # Protocol & request attacks (9)
├── httpval/                 # HTTP protocol validation (7)
├── data/                    # Data & serialization attacks (5)
├── file/                    # File & sensitive data (3)
├── session/                 # Session security (2) — outside the Engine
│   ├── store.go             # Store interface + MemoryStore
│   ├── tracker.go           # Tracker — client hijack / remote login
│   └── tamper.go            # Signer — data tampering
└── storage/                 # Pluggable storage backends
    ├── storage.go           # Backend interface
    ├── memory.go            # In-memory (with TTL cleanup)
    ├── file.go              # JSON file persistence
    └── redis/               # Redis sub-module (optional dependency)
```

## Core API

Full API reference (`Result`, `Detector`, `Engine`, storage `Backend`, HTTP validators) is in the standalone document: **[API Reference](../../api.md)**

- All detectors use pre-compiled regex patterns

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
| httpval | nested_depth | JSON body bomb: nesting depth / element count exceeded (streamed; non-JSON never matches) |
| httpval | cookie_attrs | Set-Cookie missing Secure/HttpOnly/SameSite, overlong or empty value |
| data | deserialization | PHP `O:digit:`, `C:digit:`, unserialize() |
| data | csv_injection | `=`, `@`, `+`, `-` formula prefix |
| data | mail_header | Bcc/Cc/From/To injection, MIME |
| data | jwt_attack | alg:none, kid path traversal, empty signature |
| data | prototype_pollution | `__proto__`, `constructor`, `__defineGetter__` |
| file | path_traversal | `../`, `..\\`, php://filter, null byte |
| file | upload | Extension whitelist + PHP tag content scan |
| file | data_leak | Credit card, AWS key, private key, connection string, JWT secret |
| session | session_guard | token↔client binding: UA/fingerprint change (client hijack), IP subnet/country change (remote login), login-network history |
| session | data_tamper | HMAC-SHA256 over canonical params, ±5m timestamp window, nonce replay counter |

## Non-Goals

- No general-purpose HTTP middleware — the only exception is `session.Tracker.Guard`, a thin wrapper that answers 401 when `Check` detects
- No real-time request interception (caller invokes detection)
- No attack blocking (detection only; ip_blacklist provides block-listing support)

## Implementation Status (2026-07-29)

- **All 32 detectors implemented** — entry point: `all.RegisterAll(engine)`
- **Test coverage** — 7/8 packages tested (`all` pending), httpval gained 32 tests
- **Code review complete** — 3 bugs fixed (see review report), `go vet` zero warnings
- **Known limitations** — `storage/redis/` sub-module needs `go mod tidy`; protocol package receiver style pending unification

## Addendum — session package (2026-09-15)

Session security was added as a 6th category, under the same design constraints:

- **`session.Tracker`** (`session_guard`) — `Issue` binds a token to the IP subnet / User-Agent / device fingerprint; `Check` compares on every request and fires `client_hijack` (UA or fingerprint changed, Critical) or `remote_login` (country changed Critical / subnet changed High); `Guard` answers 401 on any detection; `Observe` compares the login network against the user's history; `Revoke` ends a session immediately.
- **`session.Signer`** (`data_tamper`) — HMAC-SHA256 over parameters, `<timestamp>.<nonce>.<mac>`. Verification runs timestamp → signature → nonce counter, so a forged signature cannot burn a legitimate nonce. Replay counting reuses `storage.Backend`.
- **Storage** — a session binding cannot be expressed by `storage.Backend`, which only counts and bans, so `session.Store` (`Save` / `Load` / `Delete`) plus `MemoryStore` were added; `storage.Backend` and its three implementations are unchanged.
- **Not registered with the `Engine`** — `Detector.Detect(input string)` cannot see the token, client IP or User-Agent, so `Tracker` takes the `*http.Request` directly; `all.RegisterAll` still registers only zero-config detectors.
- **Tests** — 3 test files in `session` (store / tracker / tamper); `go test ./... -race` passes.

---

Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
