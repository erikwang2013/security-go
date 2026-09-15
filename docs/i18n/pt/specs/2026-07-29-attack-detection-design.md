# Attack Detection Package — Design Spec

## Overview

Biblioteca de detecção de ataques em Go puro, fornecendo interface unificada + padrão de registro (registry), cobrindo 6 grandes categorias e 36 detectores. **Implementação concluída (2026-07-29); o pacote `session` foi adicionado em 2026-09-15.**

## Package Structure

```
security-go/
├── go.mod
├── security.go              # Result, Severity, Detector interface, Engine
├── all/all.go               # RegisterAll — registra todos os detectors internos
├── injection/               # Ataques de injeção (10)
├── protocol/                # Ataques de protocolo e de requisição (9)
├── httpval/                 # Validação da camada de protocolo HTTP (7)
├── data/                    # Ataques de dados e serialização (5)
├── file/                    # Arquivos e dados sensíveis (3)
├── session/                 # Segurança de sessão (2) — não passa pelo Engine
│   ├── store.go             # Interface Store + MemoryStore
│   ├── tracker.go           # Tracker — sequestro do cliente / login remoto
│   ├── lockout.go           # Contador de falhas, bloqueio, chaves
│   ├── bruteforce.go        # Backoff progressivo / stuffing / GuardLogin
│   └── tamper.go            # Signer — adulteração de dados
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
| httpval | nested_depth | JSON body bomb: nesting depth / element count exceeded (streamed; non-JSON never matches) |
| httpval | cookie_attrs | Set-Cookie missing Secure/HttpOnly/SameSite, overlong or empty value |
| data | deserialization | PHP `O:número:`, `C:número:`, unserialize() |
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

- No HTTP middleware (pure detection library) — a única exceção é `session.Tracker.Guard`, um wrapper fino que responde 401 quando `Check` detecta
- No real-time request interception (caller invokes detection)
- No attack blocking (detection only; ip_blacklist provides block-listing support)

## Implementation Status (2026-07-29)

- **Todos os 32 detectors implementados** — ponto de entrada de registro `all.RegisterAll(engine)`
- **Cobertura de testes** — 7/8 pacotes têm testes (o pacote `all` está pendente), httpval ganhou 32 testes complementares
- **Revisão de código concluída** — 3 bugs corrigidos (ver relatório de revisão), `go vet` sem avisos
- **Limitações conhecidas** — o submódulo `storage/redis/` requer `go mod tidy`; o estilo de receiver do pacote protocol está pendente de padronização
- **Relatório** — `docs/superpowers/reports/2026-07-29-code-review-report.md`

## Addendum — pacote session (2026-09-15)

A segurança de sessão foi adicionada como a 6ª categoria, com as mesmas restrições de design acima:

- **`session.Tracker`** (`session_guard`) — `Issue` vincula token → sub-rede IP / UA / impressão digital; `Check` compara a cada requisição e detecta `client_hijack` (mudança de UA ou impressão digital, Critical) ou `remote_login` (entre países Critical / entre sub-redes High); `Guard` retorna 401 ao detectar; `Observe` compara com as faixas de rede históricas do usuário no login; `Revoke` invalida imediatamente.
- **`session.Signer`** (`data_tamper`) — assinatura HMAC-SHA256 dos parâmetros `<timestamp>.<nonce>.<assinatura>`, com ordem de validação timestamp → assinatura → contagem de nonce, portanto uma assinatura forjada não consome um nonce legítimo. A contagem de reenvio reutiliza `storage.Backend`.
- **Proteção contra força bruta** — `RecordFailure(identity, r)` conta falhas de login e bloqueia no limite, dobrando a cada vez até `MaxLockout` (padrão 24 h); `CheckLogin` também conta as identidades distintas por IP de cliente e reporta `credential_stuffing` em `StuffingLimit` (padrão 10); `GuardLogin` é o middleware do endpoint de autenticação, respondendo 429 com `Retry-After`. O backoff progressivo existe para que bloquear uma conta arbitrária não se torne ele próprio um vetor de DoS.
- **Armazenamento** — a estrutura de sessão não pode ser expressa com o `storage.Backend`, que só suporta contagem/bloqueio, por isso foram adicionados `session.Store` (`Save` / `Load` / `Delete`) + `MemoryStore`; `storage.Backend` e suas três implementações não foram alterados.
- **Não registrado no `Engine`** — `Detector.Detect(input string)` não obtém token / IP do cliente / UA, então `Tracker` recebe `*http.Request` diretamente; `all.RegisterAll` continua registrando apenas detectores zero-configuração.
- **Testes** — 5 arquivos de teste no pacote `session` (store / tracker / tamper / lockout / bruteforce), `go test ./... -race` passando.

---

Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
