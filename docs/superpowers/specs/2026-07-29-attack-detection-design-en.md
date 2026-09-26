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
│   ├── lockout.go           # Failure counter, lock lookup, keys
│   ├── bruteforce.go        # Progressive backoff / stuffing / GuardLogin
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
| session | session_guard | token↔client binding: UA/fingerprint change (client hijack), IP subnet/country change (remote login), login-network history; brute-force lockout with progressive backoff and per-IP credential-stuffing detection |
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
- **Brute-force protection** — `RecordFailure(identity, r)` counts login failures and locks at the threshold, doubling each episode up to `MaxLockout` (default 24h); `CheckLogin` additionally counts the distinct identities per client IP and reports `credential_stuffing` at `StuffingLimit` (default 10); `GuardLogin` is the authentication-endpoint middleware, answering 429 with `Retry-After`. Progressive backoff exists so that locking an arbitrary account cannot itself become a DoS vector.
- **Storage** — a session binding cannot be expressed by `storage.Backend`, which only counts and bans, so `session.Store` (`Save` / `Load` / `Delete`) plus `MemoryStore` were added; `storage.Backend` and its three implementations are unchanged.
- **Not registered with the `Engine`** — `Detector.Detect(input string)` cannot see the token, client IP or User-Agent, so `Tracker` takes the `*http.Request` directly; `all.RegisterAll` still registers only zero-config detectors.
- **Tests** — 5 test files in `session` (store / tracker / tamper / lockout / bruteforce); `go test ./... -race` passes.

## Addendum — pet package and documentation assets (2026-09-26)

- **The `pet` package** — the project mascot, 哨兵鼠 (Sentinel Gopher), ships as a build-time asset: `pet.SVG() []byte`, `pet.Handler() http.Handler`, `pet.Banner() string`. `go:embed` carries `pet/pet.svg`, so there is no runtime file dependency and no third-party dependency was added — the core library stays zero-dependency. `Banner()` is the startup banner as plain text (trailing newline included); `SVG()` returns a shared slice the caller must not modify.
- **`Handler` serves through `http.ServeContent`, not a bare `w.Write`** — `pet.svg` is ~6 KB, past net/http's 2 KiB response-sniff buffer, so a plain `Write` would degrade the response to chunked with no `Content-Length`; `ServeContent` also buys `Range` and a correct `HEAD`. Headers are `image/svg+xml; charset=utf-8` plus `Cache-Control: public, max-age=86400`; the handler has no side effects and belongs on a diagnostics or debug route.
- **Documentation assets** — three hand-written SVGs (architecture / feature / lifecycle), generated from the source rather than authored in Mermaid, each in a Chinese and an English variant: `docs/images/{architecture,features,lifecycle}[-en].svg`. The English variants were keyed over text nodes only, so their geometry is byte-identical to the Chinese originals (checked: the non-text lines match exactly). The two English READMEs reference the `-en` set; the other languages share the Chinese set.
- **36 and 34 are two different numbers — do not "unify" them** — 36 is the project total (27 zero-config + 7 httpval + 2 session), written into the mascot's shield, `pet.Banner`, both READMEs and all 12 translations. 34 is the subset that satisfies `security.Detector` and can be dispatched through the `Engine` (the 27 `all.RegisterAll` registers, plus the 7 httpval validators the application registers itself). `session.Tracker` and `session.Signer` expose `Name()` but not `Detect(string)`, so they are not among the 34. Both numbers are correct in their own context, and both already appear in the diagrams (`architecture.svg` "34 dispatched via the Engine", `lifecycle.svg` "34 registered in the Engine").
- **One test pins the count** — `all/all_test.go:TestTotalDetectorCountIs36` is the only place tying 36 back to the code: adding or removing a detector must fail it, and its message points at `pet/pet.svg`, `pet.Banner` and the READMEs.

---

Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
