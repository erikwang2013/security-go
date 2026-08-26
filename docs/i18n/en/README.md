# Security Go — Attack Detection Library

[简体中文](../../../README.md) · [English](../../../README-EN.md) · [API Reference](api.md)

An attack detection package written in Go, covering **32 detectors**, **5 major attack categories**, and **3 pluggable storage backends**. Unified interface + registry pattern; a pure detection library that adapts to any Go HTTP framework.

## Design Philosophy

### Core Principles

- **Zero-dependency detection** — all detectors use only the Go standard library `regexp`, no external dependencies
- **Unified interface** — every detector implements the `Detector` interface (`Name()` + `Detect()`), managed uniformly through the `Engine` registry
- **Pre-compiled regex** — all patterns are compiled at `var` initialization, zero runtime overhead
- **On-demand configuration** — injection/protocol/data/file detectors are plug-and-play; HTTP validators require application-specific configuration

### Architecture

```
                         ┌───────────────────────────────┐
                         │        security.Engine         │
                         │  ┌─────────────────────────┐  │
                         │  │    Detector Registry     │  │
                         │  │   map[string]Detector    │  │
                         │  └─────────────────────────┘  │
                         │                               │
                         │  Detect(name, input)          │
                         │  DetectAll(input)             │
                         │  DetectRequest(*http.Request) │
                         └──────────────┬────────────────┘
                                        │
          ┌─────────────────┬───────────┴───────────┬─────────────────┐
          │                 │                       │                 │
   ┌──────▼──────┐   ┌──────▼──────┐   ┌────────────▼────────┐   ┌───▼───────────┐
   │  injection  │   │  protocol   │   │        data         │   │     file      │
   │   (10 个)   │   │   (9 个)    │   │       (5 个)        │   │    (3 个)     │
   │             │   │             │   │                     │   │               │
   │  xss, sql,  │   │  ssrf, xxe, │   │  deser, csv,        │   │  traversal,   │
   │  command,   │   │  header,    │   │  mail, jwt,         │   │  upload,      │
   │  nosql,     │   │  host,      │   │  proto_poll         │   │  data_leak    │
   │  ldap,      │   │  smuggling, │   │                     │   │               │
   │  xpath,     │   │  redirect,  │   │                     │   │               │
   │  jndi, ssi, │   │  cors, ws,  │   │                     │   │               │
   │  graphql,   │   │  dns_rebind │   │                     │   │               │
   │  ssti       │   │             │   │                     │   │               │
   └─────────────┘   └─────────────┘   └─────────────────────┘   └───────────────┘
                                                                          │
          ┌───────────────────────────────────────────────────────────────┤
          │                                                               │
   ┌──────▼──────────┐                                         ┌──────────▼──────────┐
   │     httpval     │                                         │       storage       │
   │     (5 个)      │                                         │  ┌──────────────┐   │
   │                 │                                         │  │   Backend    │   │
   │  method, size,  │                                         │  │   interface  │   │
   │  type, csrf,    │                                         │  └──┬───┬───┬───┘   │
   │  ip_blacklist   │◄────── 使用 storage.Backend ──────────►│  Memory File Redis │
   │  (需配置参数)    │                                         │                    │
   └─────────────────┘                                         └────────────────────┘
```

### Data Flow

```
HTTP Request
     │
     ▼
┌──────────────┐     ┌─────────────────┐     ┌──────────────┐
│ collectInputs│────▶│  DetectAll()    │────▶│  []*Result   │
│ URL, Query,  │     │  逐个检测器调用   │     │  聚合结果     │
│ Headers,     │     │  Detect(input)  │     │              │
│ Cookies      │     └─────────────────┘     └──────────────┘
└──────────────┘
```

### Severity Levels

| Level | Description | Typical Scenarios |
|------|------|---------|
| `SeverityLow` | Low risk | Invalid HTTP method, Content-Type mismatch |
| `SeverityMedium` | Medium risk | CORS misconfiguration, open redirect, GraphQL introspection |
| `SeverityHigh` | High risk | XSS, SQL injection, SSRF, path traversal |
| `SeverityCritical` | Critical | Command injection, JNDI, SSTI, XXE, data leak |

## Features

### Injection Attacks (10)

| Detector | Detection Patterns |
|--------|---------|
| **XSS** | `<script>`, `on[a-z]+=` event handlers, `javascript:` pseudo-protocol, SVG/CSS injection, `eval()`, `document.cookie` |
| **SQL Injection** | `UNION SELECT` (including `/**/` bypass), `sleep/benchmark/pg_sleep`, boolean blind injection, `information_schema` enumeration, `xp_cmdshell` |
| **Command Injection** | Backticks, `$()`, pipe characters, `/dev/tcp`, PHP `system/exec/shell_exec`, chained execution `&&` `;` `\|\|` |
| **NoSQL Injection** | MongoDB `$ne` `$gt` `$regex` `$where` operators, `$func`, JSON key injection |
| **LDAP Injection** | Filter operators `(\|(&(!`, `objectClass=*`, URL-encoded bypass |
| **XPATH Injection** | Boolean bypass `' or '1'='1`, `string-length()`, `count()` |
| **JNDI/Log4Shell** | `${jndi:ldap://`, `${lower:j}` obfuscation, `${env:}` environment variables, `ldap/rmi/dns` protocols |
| **SSI Injection** | `<!--#exec cmd=`, `<!--#include file=`, `<!--#echo var=` |
| **GraphQL Injection** | `__schema`/`__type` introspection, deeply nested DoS (5+ layers), `mutation` detection |
| **SSTI** | Jinja2 `{{}}`, FreeMarker `${}`, ERB `<% %>`, Python MRO traversal, `config/self` access |

### Protocol & Request Attacks (9)

| Detector | Detection Patterns |
|--------|---------|
| **SSRF** | Internal IPs (127/10/172.16/192.168), `169.254.169.254`, IPv6 loopback, `gopher/dict/file/ftp` protocols |
| **XXE** | `<!ENTITY SYSTEM/PUBLIC`, parameter entities `%entity;`, DOCTYPE declarations |
| **HTTP Header Injection** | CRLF `%0d%0a` / `\r\n`, Set-Cookie/Location/Content-Length injection |
| **Host Header Attack** | CRLF Host injection, `X-Forwarded-Host`, `X-Original-URL` poisoning |
| **Request Smuggling** | Transfer-Encoding/Content-Length mismatch, dual TE headers, `\x0b` folded-header confusion |
| **Open Redirect** | `//evil.com` protocol-relative URLs, `javascript:/data:` pseudo-protocols |
| **CORS Bypass** | `Origin: null`, `Access-Control-Allow-*` header injection |
| **WebSocket Hijacking** | Upgrade header injection, null Origin bypass, `ws://` URLs |
| **DNS Rebinding** | Internal IP in Host header, localhost, short hostnames without TLD |

### HTTP Protocol-Layer Validation (5)

| Detector | Description |
|--------|------|
| **HTTP Method** | Only GET/POST/PUT/DELETE/HEAD/OPTIONS/PATCH allowed, others return a warning |
| **Request Body Size** | Warning when exceeding the limit (default 10MB) |
| **Content-Type** | Only the configured MIME type whitelist is allowed |
| **CSRF Origin** | Checks whether the Origin of cross-origin requests matches the Host, supports an additional whitelist |
| **IP Blacklist** | Automatic ban after N attacks within the window (default 5/60s → 15-minute ban), supports File/Redis/Memory storage |

### Data & Serialization Attacks (5)

| Detector | Detection Patterns |
|--------|---------|
| **PHP Deserialization** | `O:digits:` / `C:digits:` serialized objects, `unserialize()`, magic methods (`__wakeup`/`__destruct`) |
| **CSV Injection** | `=cmd\|`, `@SUM(`, `+`/`-` formula prefixes, `HYPERLINK`/`DDE` |
| **Mail Header Injection** | Bcc/Cc/From/To injection, MIME multipart, boundary parameters |
| **JWT Attack** | `alg: none` bypass, `kid` path traversal, empty-signature detection (structural decode analysis) |
| **Prototype Pollution** | `__proto__`/`constructor` keys, `__defineGetter__`/`__defineSetter__` |

### File & Sensitive Data (3)

| Detector | Detection Patterns |
|--------|---------|
| **Path Traversal** | `../`, `..\\`, `php://filter`/`php://input`, null bytes, URL-encoded bypass, `/etc/passwd` |
| **Malicious Upload** | Extension whitelist (15 types) + PHP tag `<?php`/`<?=` content scan |
| **Data Leak** | Credit card numbers, AWS Access Keys, private keys `-----BEGIN`, database connection strings, API tokens, JWT secrets, GitHub PATs |

### Storage Backends (3)

| Backend | Description |
|------|------|
| **Memory** | `sync.Mutex` + map, auto-cleans expired entries every 30s |
| **File** | JSON file persistence, flushes on Close |
| **Redis** | Standalone submodule, Pipeline Incr + TTL, requires `go-redis/v9` |

## Usage

### Installation

```bash
go get github.com/erikwang2013/security-go
```

### Quick Start

```go
package main

import (
    "fmt"
    "github.com/erikwang2013/security-go"
    "github.com/erikwang2013/security-go/all"
)

func main() {
    e := security.NewEngine()
    all.RegisterAll(e) // 一键注册 27 个零配置检测器

    // 单个检测
    r := e.Detect("xss", "<script>alert(1)</script>")
    fmt.Printf("检测到: %v, 严重程度: %d\n", r.Detected, r.Severity)

    // 全量检测
    for _, r := range e.DetectAll("' OR '1'='1") {
        fmt.Printf("[%s] %s\n", r.Name, r.Message)
    }
}
```

### HTTP Request Detection

```go
func handler(w http.ResponseWriter, r *http.Request) {
    e := security.NewEngine()
    all.RegisterAll(e)

    for _, result := range e.DetectRequest(r) {
        if result.Detected {
            log.Printf("攻击检测: [%s] %s", result.Name, result.Message)
        }
    }
}
```

### HTTP Validator Configuration

```go
// 方法校验
e.Register(&httpval.Method{})

// 请求体大小限制
e.Register(httpval.NewBodySize(5 * 1024 * 1024)) // 5MB

// Content-Type 白名单
e.Register(httpval.NewContentType([]string{
    "application/json", "application/x-www-form-urlencoded",
}))

// CSRF Origin 检查
e.Register(&httpval.CSRFOrigin{
    Host: "example.com", AllowList: []string{"api.example.com"},
})

// IP 黑名单（自动封禁：5次/60s → 封禁15分钟）
mem := storage.NewMemory()
defer mem.Close()
bl := httpval.NewIPBlacklist(mem)
e.Register(bl)

// 攻击发生时记录
blocked, _ := bl.RecordAttack(clientIP)
```

### Custom Detector

```go
type MyDetector struct{}

func (d *MyDetector) Name() string { return "my_detector" }

func (d *MyDetector) Detect(input string) *security.Result {
    return &security.Result{
        Name: "my_detector", Detected: strings.Contains(input, "evil"),
        Severity: security.SeverityHigh, Message: "检测到恶意内容",
    }
}

e.Register(&MyDetector{})
```

### Related Documents

- [API Reference](api.md) — core types, Detector/Engine interfaces, storage backend interface, HTTP validators
- [Design Spec](specs/2026-07-29-attack-detection-design.md) — package structure, detector catalog
- [Implementation Plan](plans/2026-07-29-attack-detection-plan.md) — step-by-step task plan and implementation deviations
- [Code Review Report](reports/2026-07-29-code-review-report.md) — bug fixes, test coverage, architecture assessment

---

## Languages

| Language | Documentation |
|------|------|
| 简体中文 | [README.md](../../../README.md) |
| English | [README.md](README.md) · [docs/i18n/README.md](../README.md) |
| 한국어 | [docs/i18n/ko/README.md](../ko/README.md) |
| Русский | [docs/i18n/ru/README.md](../ru/README.md) |
| Deutsch | [docs/i18n/de/README.md](../de/README.md) |
| Français | [docs/i18n/fr/README.md](../fr/README.md) |
| Español | [docs/i18n/es/README.md](../es/README.md) |
| Português | [docs/i18n/pt/README.md](../pt/README.md) |
| हिन्दी | [docs/i18n/hi/README.md](../hi/README.md) |
| العربية | [docs/i18n/ar/README.md](../ar/README.md) |
| বাংলা | [docs/i18n/bn/README.md](../bn/README.md) |
| Bahasa Indonesia | [docs/i18n/id/README.md](../id/README.md) |
| 日本語 | [docs/i18n/ja/README.md](../ja/README.md) |

Index of all languages: [docs/i18n/README.md](../README.md)

---

## Donation Support

If this project is helpful to you, donations are welcome:

| Method | QR Code |
|------|--------|
| Alipay | ![Alipay](images/alipay.png) |
| WeChat Pay | ![WeChat Pay](images/weixinpay.png) |

### Global Wire Transfer Donation (Bank Transfer)

**Payee Information**

- Payee Name: WANG KEXUN
- Payee Account Number: 881015918251

**Receiving Bank (ZA Bank)**

- SWIFT Code: `AABLHKHHXXX`
- Bank Name: ZA Bank Limited
- Bank Code: 387
- Bank Address: Core F, Cyberport 3, 100 Cyberport Road, Hong Kong

**Cross-Border Remittance Correspondent Bank (If Required)**

> Please note that this is the correspondent bank (intermediary bank) information for cross-border remittances, not the receiving bank information. Please ask your remitting bank whether correspondent bank information is required.

- For remittances in HKD, CNY, and USD, the correspondent bank is Citibank:
  - Bank Name: Citibank N.A. Hong Kong
  - SWIFT Code: `CITIHKHXXXX`
  - Bank Code: 006
  - Branch Name: Hong Kong Branch
  - Branch Code: 391
  - Bank Address: Citibank Tower, Citibank Plaza, 3 Garden Road, Central, Hong Kong
- For remittances in other currencies, the correspondent bank is BNY Mellon:
  - Bank Name: THE BANK OF NEW YORK MELLON
  - SWIFT Code: `IRVTUS3NXXX`
  - Bank Address: THE BANK OF NEW YORK MELLON, 240 GREENWICH STREET, NEW YORK, United States

---

## English

See [README-EN.md](../../../README-EN.md) for the full English documentation.

---

Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
