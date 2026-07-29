# Security Go — 攻击检测库

[English](#english)

Go 语言编写的攻击检测包，覆盖 **32 个检测器**、**5 大攻击类别**、**3 种可插拔存储后端**。统一接口 + 注册表模式，纯检测库，适配任何 Go HTTP 框架。

## 设计思路

### 核心原则

- **零依赖检测** — 所有检测器仅使用 Go 标准库 `regexp`，无外部依赖
- **统一接口** — 每个检测器实现 `Detector` 接口（`Name()` + `Detect()`），通过 `Engine` 注册表统一管理
- **预编译正则** — 所有模式在 `var` 初始化时编译，运行时零开销
- **按需配置** — 注入/协议/数据/文件检测器即插即用；HTTP 校验器需应用自定义配置

### 设计架构

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

### 数据流

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

### 严重程度分级

| 级别 | 说明 | 典型场景 |
|------|------|---------|
| `SeverityLow` | 低风险 | 非法 HTTP 方法、Content-Type 不匹配 |
| `SeverityMedium` | 中风险 | CORS 配置问题、开放重定向、GraphQL 内省 |
| `SeverityHigh` | 高风险 | XSS、SQL 注入、SSRF、路径遍历 |
| `SeverityCritical` | 严重 | 命令注入、JNDI、SSTI、XXE、数据泄露 |

## 实现功能

### 注入类攻击 (10)

| 检测器 | 检测模式 |
|--------|---------|
| **XSS** | `<script>`、`on[a-z]+=` 事件处理器、`javascript:` 伪协议、SVG/CSS 注入、`eval()`、`document.cookie` |
| **SQL 注入** | `UNION SELECT`（含 `/**/` 绕过）、`sleep/benchmark/pg_sleep`、布尔盲注、`information_schema` 枚举、`xp_cmdshell` |
| **命令注入** | 反引号、`$()`、管道符、`/dev/tcp`、PHP `system/exec/shell_exec`、链式执行 `&&` `;` `\|\|` |
| **NoSQL 注入** | MongoDB `$ne` `$gt` `$regex` `$where` 操作符、`$func`、JSON 键注入 |
| **LDAP 注入** | 过滤操作符 `(\|(&(!`、`objectClass=*`、URL 编码绕过 |
| **XPATH 注入** | 布尔绕过 `' or '1'='1`、`string-length()`、`count()` |
| **JNDI/Log4Shell** | `${jndi:ldap://`、`${lower:j}` 混淆、`${env:}` 环境变量、`ldap/rmi/dns` 协议 |
| **SSI 注入** | `<!--#exec cmd=`、`<!--#include file=`、`<!--#echo var=` |
| **GraphQL 注入** | `__schema`/`__type` 内省、深度嵌套 DoS（5层+）、`mutation` 检测 |
| **SSTI** | Jinja2 `{{}}`、FreeMarker `${}`、ERB `<% %>`、Python MRO 遍历、`config/self` 访问 |

### 协议与请求攻击 (9)

| 检测器 | 检测模式 |
|--------|---------|
| **SSRF** | 内网 IP（127/10/172.16/192.168）、`169.254.169.254`、IPv6 loopback、`gopher/dict/file/ftp` 协议 |
| **XXE** | `<!ENTITY SYSTEM/PUBLIC`、参数实体 `%entity;`、DOCTYPE 声明 |
| **HTTP 头注入** | CRLF `%0d%0a` / `\r\n`、Set-Cookie/Location/Content-Length 注入 |
| **Host 头攻击** | CRLF Host 注入、`X-Forwarded-Host`、`X-Original-URL` 投毒 |
| **请求走私** | Transfer-Encoding/Content-Length 不一致、双重 TE 头、`\x0b` 折叠头混淆 |
| **开放重定向** | `//evil.com` 协议相对 URL、`javascript:/data:` 伪协议 |
| **CORS 绕过** | `Origin: null`、`Access-Control-Allow-*` 头注入 |
| **WebSocket 劫持** | Upgrade 头注入、null Origin 绕过、`ws://` URL |
| **DNS 重绑定** | Host 头内网 IP、localhost、无 TLD 短主机名 |

### HTTP 协议层校验 (5)

| 检测器 | 说明 |
|--------|------|
| **HTTP 方法** | 仅允许 GET/POST/PUT/DELETE/HEAD/OPTIONS/PATCH，其他返回告警 |
| **请求体大小** | 超过上限（默认 10MB）触发告警 |
| **Content-Type** | 仅允许配置的 MIME 类型白名单 |
| **CSRF Origin** | 检测跨域请求 Origin 与 Host 是否匹配，支持额外白名单 |
| **IP 黑名单** | 窗口时间 N 次攻击后自动封禁（默认 5次/60s→封禁15分钟），支持 File/Redis/Memory 存储 |

### 数据与序列化攻击 (5)

| 检测器 | 检测模式 |
|--------|---------|
| **PHP 反序列化** | `O:数字:` / `C:数字:` 序列化对象、`unserialize()`、魔术方法（`__wakeup`/`__destruct`） |
| **CSV 注入** | `=cmd\|`、`@SUM(`、`+`/`-` 公式前缀、`HYPERLINK`/`DDE` |
| **邮件头注入** | Bcc/Cc/From/To 注入、MIME multipart、boundary 参数 |
| **JWT 攻击** | `alg: none` 绕过、`kid` 路径遍历、空签名检测（结构解码分析） |
| **原型污染** | `__proto__`/`constructor` 键、`__defineGetter__`/`__defineSetter__` |

### 文件与敏感数据 (3)

| 检测器 | 检测模式 |
|--------|---------|
| **路径遍历** | `../`、`..\\`、`php://filter`/`php://input`、null 字节、URL 编码绕过、`/etc/passwd` |
| **恶意上传** | 扩展名白名单（15种）+ PHP 标签 `<?php`/`<?=` 内容扫描 |
| **数据泄露** | 信用卡号、AWS Access Key、私钥 `-----BEGIN`、数据库连接串、API Token、JWT Secret、GitHub PAT |

### 存储后端 (3)

| 后端 | 说明 |
|------|------|
| **Memory** | `sync.Mutex` + map，30s 自动清理过期条目 |
| **File** | JSON 文件持久化，Close 时 flush |
| **Redis** | 独立子模块，Pipeline Incr + TTL，需 `go-redis/v9` |

## 使用说明

### 安装

```bash
go get github.com/bag/security-go
```

### 快速开始

```go
package main

import (
    "fmt"
    "github.com/bag/security-go"
    "github.com/bag/security-go/all"
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

### HTTP 请求检测

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

### HTTP 校验器配置

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

### 自定义检测器

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

### 相关文档

- [设计规范](docs/superpowers/specs/2026-07-29-attack-detection-design.md) — 包结构、核心 API、检测器目录
- [实施计划](docs/superpowers/plans/2026-07-29-attack-detection-plan.md) — 分步任务计划与实施偏差对照
- [代码审查报告](docs/superpowers/reports/2026-07-29-code-review-report.md) — Bug 修复、测试覆盖、架构评估

---

## English

[中文](#security-go--攻击检测库)

A pure Go attack detection library with **32 detectors** across **5 categories**, **3 pluggable storage backends**, and a unified `Detector` interface + `Engine` registry. Zero external dependencies for all detection logic.

### Quick Start

```go
e := security.NewEngine()
all.RegisterAll(e)
result := e.Detect("xss", "<script>alert(1)</script>")
```

### Categories

- **Injection (10):** XSS, SQLi, Command, NoSQL, LDAP, XPATH, JNDI/Log4Shell, SSI, GraphQL, SSTI
- **Protocol (9):** SSRF, XXE, Header Injection, Host Header, Request Smuggling, Open Redirect, CORS, WebSocket, DNS Rebinding
- **HTTP Validation (5):** Method, Body Size, Content-Type, CSRF Origin, IP Blacklist
- **Data (5):** PHP Deserialization, CSV Injection, Mail Header, JWT Attack, Prototype Pollution
- **File (3):** Path Traversal, Malicious Upload, Data Leak

### Storage

- **Memory** — `sync.Mutex` + map, 30s TTL cleanup
- **File** — JSON persistence, flush on Close
- **Redis** — Pipeline Incr + TTL (separate sub-module)

See [Chinese section](#security-go--攻击检测库) above for full API reference and detector details.

### Documentation

- [Design Spec](docs/superpowers/specs/2026-07-29-attack-detection-design-en.md) — Package structure, core API, detector catalog
- [Implementation Plan](docs/superpowers/plans/2026-07-29-attack-detection-plan-en.md) — Task-by-task plan with actual vs planned deviations
- [Code Review Report](docs/superpowers/reports/2026-07-29-code-review-report-en.md) — Bug fixes, test coverage, architecture review

---

Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
