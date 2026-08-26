# Security Go — biblioteca de detecção de ataques

[简体中文](../../../README.md) · [English](../../../README-EN.md) · [Documentação da API](api.md)

Pacote de detecção de ataques escrito em Go, cobrindo **32 detectores**, **5 grandes categorias de ataques** e **3 backends de armazenamento plugáveis**. Interface unificada + padrão de registro (registry), biblioteca pura de detecção, compatível com qualquer framework HTTP em Go.

## Filosofia de design

### Princípios centrais

- **Detecção zero-dependência** — todos os detectores usam apenas `regexp` da biblioteca padrão do Go, sem dependências externas
- **Interface unificada** — cada detector implementa a interface `Detector` (`Name()` + `Detect()`), gerenciado de forma unificada pelo registro `Engine`
- **Regex pré-compiladas** — todos os padrões são compilados na inicialização de `var`, zero custo em tempo de execução
- **Configuração sob demanda** — detectores de injeção/protocolo/dados/arquivo são plug-and-play; validadores HTTP exigem configuração personalizada da aplicação

### Arquitetura de design

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

### Fluxo de dados

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

### Níveis de severidade

| Nível | Descrição | Cenários típicos |
|------|------|---------|
| `SeverityLow` | Baixo risco | Método HTTP inválido, Content-Type incompatível |
| `SeverityMedium` | Risco médio | Problemas de configuração CORS, redirecionamento aberto, introspecção GraphQL |
| `SeverityHigh` | Alto risco | XSS, injeção de SQL, SSRF, path traversal |
| `SeverityCritical` | Crítico | Injeção de comandos, JNDI, SSTI, XXE, vazamento de dados |

## Funcionalidades implementadas

### Ataques de injeção (10)

| Detector | Padrões de detecção |
|--------|---------|
| **XSS** | `<script>`, manipuladores de eventos `on[a-z]+=`, pseudo-protocolo `javascript:`, injeção SVG/CSS, `eval()`, `document.cookie` |
| **Injeção de SQL** | `UNION SELECT` (incluindo bypass `/**/`), `sleep/benchmark/pg_sleep`, blind SQL injection booleano, enumeração `information_schema`, `xp_cmdshell` |
| **Injeção de comandos** | crase, `$()`, pipe `\|`, `/dev/tcp`, funções PHP `system/exec/shell_exec`, execução encadeada `&&` `;` `\|\|` |
| **Injeção NoSQL** | Operadores do MongoDB `$ne` `$gt` `$regex` `$where`, `$func`, injeção de chaves JSON |
| **Injeção LDAP** | Operadores de filtro `(\|(&(!`, `objectClass=*`, bypass por URL encoding |
| **Injeção XPATH** | Bypass booleano `' or '1'='1`, `string-length()`, `count()` |
| **JNDI/Log4Shell** | `${jndi:ldap://`, ofuscação `${lower:j}`, variáveis de ambiente `${env:}`, protocolos `ldap/rmi/dns` |
| **Injeção SSI** | `<!--#exec cmd=`, `<!--#include file=`, `<!--#echo var=` |
| **Injeção GraphQL** | Introspecção `__schema`/`__type`, DoS por aninhamento profundo (5+ níveis), detecção de `mutation` |
| **SSTI** | Jinja2 `{{}}`, FreeMarker `${}`, ERB `<% %>`, travessia MRO do Python, acesso a `config/self` |

### Ataques de protocolo e de requisição (9)

| Detector | Padrões de detecção |
|--------|---------|
| **SSRF** | IPs internos (127/10/172.16/192.168), `169.254.169.254`, loopback IPv6, protocolos `gopher/dict/file/ftp` |
| **XXE** | `<!ENTITY SYSTEM/PUBLIC`, entidades de parâmetro `%entity;`, declaração DOCTYPE |
| **Injeção de cabeçalho HTTP** | CRLF `%0d%0a` / `\r\n`, injeção em Set-Cookie/Location/Content-Length |
| **Ataque de cabeçalho Host** | Injeção CRLF no Host, envenenamento de `X-Forwarded-Host`, `X-Original-URL` |
| **Request smuggling** | Inconsistência Transfer-Encoding/Content-Length, cabeçalhos TE duplicados, ofuscação de cabeçalho dobrado `\x0b` |
| **Redirecionamento aberto** | URL relativa de protocolo `//evil.com`, pseudo-protocolos `javascript:/data:` |
| **Bypass de CORS** | `Origin: null`, injeção de cabeçalhos `Access-Control-Allow-*` |
| **Sequestro de WebSocket** | Injeção no cabeçalho Upgrade, bypass de Origin null, URL `ws://` |
| **DNS rebinding** | IP interno no cabeçalho Host, localhost, hostnames curtos sem TLD |

### Validação da camada de protocolo HTTP (5)

| Detector | Descrição |
|--------|------|
| **Método HTTP** | Apenas GET/POST/PUT/DELETE/HEAD/OPTIONS/PATCH são permitidos; demais retornam alerta |
| **Tamanho do corpo da requisição** | Exceder o limite (padrão 10MB) dispara alerta |
| **Content-Type** | Apenas a lista de permissão de tipos MIME configurada |
| **Origem CSRF** | Verifica se Origin de requisições cross-origin corresponde ao Host, com suporte a lista de permissão adicional |
| **Blacklist de IP** | Banimento automático após N ataques na janela de tempo (padrão 5 vezes/60s → banimento de 15 minutos), com suporte a armazenamento File/Redis/Memory |

### Ataques de dados e serialização (5)

| Detector | Padrões de detecção |
|--------|---------|
| **Desserialização PHP** | Objetos serializados `O:número:` / `C:número:`, `unserialize()`, métodos mágicos (`__wakeup`/`__destruct`) |
| **Injeção CSV** | `=cmd\|`, `@SUM(`, prefixos de fórmula `+`/`-`, `HYPERLINK`/`DDE` |
| **Injeção de cabeçalho de e-mail** | Injeção em Bcc/Cc/From/To, MIME multipart, parâmetro boundary |
| **Ataques JWT** | Bypass `alg: none`, path traversal em `kid`, detecção de assinatura vazia (análise de decodificação estrutural) |
| **Poluição de protótipo** | Chaves `__proto__`/`constructor`, `__defineGetter__`/`__defineSetter__` |

### Arquivos e dados sensíveis (3)

| Detector | Padrões de detecção |
|--------|---------|
| **Path traversal** | `../`, `..\\`, `php://filter`/`php://input`, byte nulo, bypass por URL encoding, `/etc/passwd` |
| **Upload malicioso** | Lista de permissão de extensões (15 tipos) + varredura de conteúdo com tags PHP `<?php`/`<?=` |
| **Vazamento de dados** | Números de cartão de crédito, AWS Access Key, chaves privadas `-----BEGIN`, strings de conexão de banco de dados, API Token, JWT Secret, GitHub PAT |

### Backends de armazenamento (3)

| Backend | Descrição |
|------|------|
| **Memory** | `sync.Mutex` + map, limpeza automática de entradas expiradas a cada 30s |
| **File** | Persistência em arquivo JSON, flush no Close |
| **Redis** | Submódulo independente, Pipeline Incr + TTL, requer `go-redis/v9` |

## Instruções de uso

### Instalação

```bash
go get github.com/erikwang2013/security-go
```

### Início rápido

```go
package main

import (
    "fmt"
    "github.com/erikwang2013/security-go"
    "github.com/erikwang2013/security-go/all"
)

func main() {
    e := security.NewEngine()
    all.RegisterAll(e) // registra 27 detectores zero-configuração de uma vez

    // Detecção individual
    r := e.Detect("xss", "<script>alert(1)</script>")
    fmt.Printf("Detectado: %v, severidade: %d\n", r.Detected, r.Severity)

    // Detecção completa
    for _, r := range e.DetectAll("' OR '1'='1") {
        fmt.Printf("[%s] %s\n", r.Name, r.Message)
    }
}
```

### Detecção de requisições HTTP

```go
func handler(w http.ResponseWriter, r *http.Request) {
    e := security.NewEngine()
    all.RegisterAll(e)

    for _, result := range e.DetectRequest(r) {
        if result.Detected {
            log.Printf("Ataque detectado: [%s] %s", result.Name, result.Message)
        }
    }
}
```

### Configuração dos validadores HTTP

```go
// Validação de método
e.Register(&httpval.Method{})

// Limite de tamanho do corpo da requisição
e.Register(httpval.NewBodySize(5 * 1024 * 1024)) // 5MB

// Lista de permissão de Content-Type
e.Register(httpval.NewContentType([]string{
    "application/json", "application/x-www-form-urlencoded",
}))

// Verificação de origem CSRF
e.Register(&httpval.CSRFOrigin{
    Host: "example.com", AllowList: []string{"api.example.com"},
})

// Blacklist de IP (banimento automático: 5 vezes/60s → banimento de 15 min)
mem := storage.NewMemory()
defer mem.Close()
bl := httpval.NewIPBlacklist(mem)
e.Register(bl)

// Registro quando um ataque ocorre
blocked, _ := bl.RecordAttack(clientIP)
```

### Detector personalizado

```go
type MyDetector struct{}

func (d *MyDetector) Name() string { return "my_detector" }

func (d *MyDetector) Detect(input string) *security.Result {
    return &security.Result{
        Name: "my_detector", Detected: strings.Contains(input, "evil"),
        Severity: security.SeverityHigh, Message: "conteúdo malicioso detectado",
    }
}

e.Register(&MyDetector{})
```

### Documentação relacionada

- [Documentação da API](api.md) — tipos centrais, interfaces Detector/Engine, interface de backend de armazenamento, validadores HTTP
- [Especificação de design](specs/2026-07-29-attack-detection-design.md) — estrutura do pacote, diretório de detectores
- [Plano de implementação](plans/2026-07-29-attack-detection-plan.md) — plano de tarefas passo a passo e comparação de desvios de implementação
- [Relatório de revisão de código](reports/2026-07-29-code-review-report.md) — correções de bugs, cobertura de testes, avaliação de arquitetura

---

## Documentação multilíngue

| Idioma | Documento |
|------|------|
| 简体中文 | [README.md](../../../README.md) |
| English | [README-EN.md](../../../README-EN.md) · [docs/i18n/en/README.md](../en/README.md) |
| 한국어 | [docs/i18n/ko/README.md](../ko/README.md) |
| Русский | [docs/i18n/ru/README.md](../ru/README.md) |
| Deutsch | [docs/i18n/de/README.md](../de/README.md) |
| Français | [docs/i18n/fr/README.md](../fr/README.md) |
| Español | [docs/i18n/es/README.md](../es/README.md) |
| Português | [README.md](README.md) |
| हिन्दी | [docs/i18n/hi/README.md](../hi/README.md) |
| العربية | [docs/i18n/ar/README.md](../ar/README.md) |
| বাংলা | [docs/i18n/bn/README.md](../bn/README.md) |
| Bahasa Indonesia | [docs/i18n/id/README.md](../id/README.md) |
| 日本語 | [docs/i18n/ja/README.md](../ja/README.md) |

Índice de todas as traduções: [docs/i18n/README.md](../README.md)

---

## Apoio por doação

Se este projeto ajudou você, fique à vontade para apoiar com uma doação:

| Forma | QR Code |
|------|--------|
| Alipay | ![Alipay](images/alipay.png) |
| WeChat Pay | ![WeChat Pay](images/weixinpay.png) |

### Doação por transferência bancária internacional

**Dados do beneficiário**

- Nome do beneficiário: WANG KEXUN
- Número da conta do beneficiário: 881015918251

**Banco do beneficiário (ZA Bank)**

- SWIFT Code：`AABLHKHHXXX`
- Nome do banco：ZA Bank Limited
- Código do banco：387
- Endereço do banco：Core F, Cyberport 3, 100 Cyberport Road, Hong Kong

**Banco intermediário para transferências transfronteiriças (se necessário)**

> Observe que estas são as informações do banco intermediário (banco correspondente) para transferências transfronteiriças, e não do banco beneficiário. Consulte o banco remetente sobre a necessidade de fornecer as informações do banco intermediário.

- Para remessas em dólares de Hong Kong, renminbi e dólares americanos, o banco intermediário é o Citibank:
  - Nome do banco：Citibank N.A. Hong Kong
  - SWIFT Code：`CITIHKHXXXX`
  - Código do banco：006
  - Nome da agência：Hong Kong Branch
  - Código da agência：391
  - Endereço do banco：Citibank Tower, Citibank Plaza, 3 Garden Road, Central, Hong Kong
- Para remessas em outras moedas, o banco intermediário é o BNY Mellon:
  - Nome do banco：THE BANK OF NEW YORK MELLON
  - SWIFT Code：`IRVTUS3NXXX`
  - Endereço do banco：THE BANK OF NEW YORK MELLON, 240 GREENWICH STREET, NEW YORK, United States

---

## English

See [README-EN.md](../../../README-EN.md) for the full English documentation.

---

Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
