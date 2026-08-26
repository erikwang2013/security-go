# Attack Detection Package — Design Spec

## Overview

Biblioteca de detecção de ataques em Go puro, fornecendo interface unificada + padrão de registro (registry), cobrindo 5 grandes categorias e 32 detectores. **Implementação concluída (2026-07-29).**

## Package Structure

```
security-go/
├── go.mod
├── security.go              # Result, Severity, Detector interface, Engine
├── all/all.go               # RegisterAll — registra todos os detectors internos
├── injection/               # Ataques de injeção (10)
├── protocol/                # Ataques de protocolo e de requisição (9)
├── httpval/                 # Validação da camada de protocolo HTTP (5)
├── data/                    # Ataques de dados e serialização (5)
├── file/                    # Arquivos e dados sensíveis (3)
└── storage/                 # Backends de armazenamento plugáveis
    ├── storage.go           # Backend interface
    ├── memory.go            # Implementação em memória (com limpeza por TTL)
    ├── file.go              # Persistência em arquivo JSON
    └── redis/               # Submódulo Redis (dependência opcional)
```

## Core API

As APIs completas (`Result`, `Detector`, `Engine`, backend de armazenamento `Backend`, validadores HTTP) estão no documento separado: **[Documentação da API](../api.md)**

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
| httpval | method | Whitelist GET/POST/PUT/DELETE/HEAD/OPTIONS/PATCH → 405 |
| httpval | body_size | Max size check → 413 (default 10MB) |
| httpval | content_type | MIME whitelist → 415 |
| httpval | csrf_origin | Cross-origin Origin vs Host match |
| httpval | ip_blacklist | Window-based rate limit → auto ban (5/60s → 15min) |
| data | deserialization | PHP `O:número:`, `C:número:`, unserialize() |
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

- **Todos os 32 detectors implementados** — ponto de entrada de registro `all.RegisterAll(engine)`
- **Cobertura de testes** — 7/8 pacotes têm testes (o pacote `all` está pendente), httpval ganhou 32 testes complementares
- **Revisão de código concluída** — 3 bugs corrigidos (ver relatório de revisão), `go vet` sem avisos
- **Limitações conhecidas** — o submódulo `storage/redis/` requer `go mod tidy`; o estilo de receiver do pacote protocol está pendente de padronização
- **Relatório** — `docs/superpowers/reports/2026-07-29-code-review-report.md`

---

Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
