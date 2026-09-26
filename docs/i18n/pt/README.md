# Security Go — biblioteca de detecção de ataques

[简体中文](../../../README.md) · [English](../../../README-EN.md) · [Documentação da API](api.md)

Pacote de detecção de ataques escrito em Go, cobrindo **36 detectores**, **6 grandes categorias de ataques** e **3 backends de armazenamento plugáveis**. Interface unificada + padrão de registro (registry), biblioteca pura de detecção, compatível com qualquer framework HTTP em Go.

<p align="center">
  <img src="../../../pet/pet.svg" width="190" alt="Sentinel Gopher">
  <br>
  <sub>Mascote do projeto Sentinel Gopher(哨兵鼠) — um gopher Go montando guarda com um escudo. O 36 no escudo é o número de detectores; a lupa é a varredura por requisição.</sub>
</p>

[Arquitetura de design](#arquitetura-de-design) · [Funcionalidades implementadas](#funcionalidades-implementadas) · [Ciclo de vida](#ciclo-de-vida) · [Estrutura do projeto](#estrutura-do-projeto) · [O mascote](#o-mascote)

## Filosofia de design

### Princípios centrais

- **Detecção zero-dependência** — todos os detectores usam apenas `regexp` da biblioteca padrão do Go, sem dependências externas
- **Interface unificada** — cada detector implementa a interface `Detector` (`Name()` + `Detect()`), gerenciado de forma unificada pelo registro `Engine`
- **Regex pré-compiladas** — todos os padrões são compilados na inicialização de `var`, zero custo em tempo de execução
- **Configuração sob demanda** — detectores de injeção/protocolo/dados/arquivo são plug-and-play; validadores HTTP e detectores de segurança de sessão exigem configuração personalizada da aplicação

### Arquitetura de design

![Arquitetura de design](../../../docs/images/architecture.svg)

> O pacote `session` não passa pelo registro `Engine`: a validação de sessão precisa ler o `*http.Request` completo (token, IP do cliente, User-Agent),
> e exige que a aplicação forneça armazenamento e chave, por isso é chamado diretamente como middleware, veja 「Configuração de segurança de sessão」 abaixo.

### Ciclo de vida

O ciclo completo de uma requisição, da entrada à detecção até o tratamento graduado (incluindo o ciclo de banimento de IP e a reanálise por decodificação de URL), mais a jornada de uma sessão da vinculação à revogação:

![Ciclo de vida](../../../docs/images/lifecycle.svg)

### Níveis de severidade

| Nível | Descrição | Cenários típicos |
|------|------|---------|
| `SeverityLow` | Baixo risco | Método HTTP inválido, Content-Type incompatível |
| `SeverityMedium` | Risco médio | Sinais fracos: má configuração de CORS, redirecionamento aberto, introspecção GraphQL, mais os padrões sem contexto que cada detector separa de propósito (`../`, `on…=`, `javascript:`, `sleep(`, `sqlite_master`, crases, `{#…#}`, `__proto__:`, nomes de métodos mágicos PHP) — comuns em tutoriais e conteúdo comum |
| `SeverityHigh` | Alto risco | Sinais fortes: XSS, injeção de SQL, SSRF, path traversal, anomalias de sessão |
| `SeverityCritical` | Crítico | Sinais fortes: injeção de comandos, JNDI, SSTI, XXE, vazamento de dados, desserialização (objetos serializados PHP / pickle / Java / .NET) |

## Funcionalidades implementadas

### Visão geral das funcionalidades

![Design das funcionalidades](../../../docs/images/features.svg)

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

### Validação da camada de protocolo HTTP (7)
| **Profundidade de aninhamento JSON** | Analisa em streaming com `json.Decoder`: sinaliza uma bomba JSON quando a profundidade ou o número de elementos excede o limite (profundidade padrão 32). JSON inválido ou truncado nunca alerta |
| **Atributos de Set-Cookie** | Sinaliza `Set-Cookie` sem `Secure`/`HttpOnly`/`SameSite`, com valor longo demais ou vazio; atributos ausentes agrupados em um único resultado |

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
| **Desserialização** | Objetos serializados `O:número:` / `C:número:`, `unserialize()`, métodos mágicos (`__wakeup`/`__destruct`); cobre cargas PHP / pickle / Java / .NET |
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

### Segurança de sessão (2)

| Detector | Padrões de detecção |
|--------|---------|
| **Guarda de sessão** (`session_guard`) | Vincula o token ao cliente no momento de criação da sessão e compara a cada requisição: mudança de User-Agent ou de impressão digital do dispositivo é julgada como **sequestro do cliente** (Critical); IP do cliente caindo em outra sub-rede ou país é julgado como **login remoto** (High/Critical); `Observe()` compara as faixas de rede históricas no login e alerta quando surge uma nova. A sessão é renovada por sliding, e `Revoke()` a invalida imediatamente; `RecordFailure()` conta as tentativas falhas e bloqueia o token ao atingir o limite dentro da janela, `Check()` passa a reportar `token_locked`, e `ClearFailures()` zera o contador após um login bem-sucedido; `CheckLogin()` também detecta credential stuffing (um cliente falhando contra identidades distintas demais reporta `credential_stuffing`), e o bloqueio dobra a cada repetição, limitado a 24 h |
| **Adulteração de dados** (`data_tamper`) | Assinatura HMAC-SHA256 sobre os parâmetros da requisição (`timestamp.nonce.assinatura`), identificando alteração de parâmetros, chave incorreta, timestamp fora da tolerância e reenvio de assinatura (contador de nonce) |

### Backends de armazenamento (3)

| Backend | Descrição |
|------|------|
| **Memory** | `sync.Mutex` + map, limpeza automática de entradas expiradas a cada 30s |
| **File** | Persistência em arquivo JSON, flush no Close |
| **Redis** | Submódulo independente, Pipeline Incr + TTL, requer `go-redis/v9` |

## Estrutura do projeto

```
security-go/
├── security.go            # Núcleo: Result / Severity / interface Detector / registro Engine
├── injection/             # Detectores de injeção (10): xss, sql, command, nosql, ldap,
│                          #   xpath, jndi, ssi, graphql, ssti
├── protocol/              # Detectores de protocolo e requisição (9): ssrf, xxe, header, host,
│                          #   smuggling, redirect, cors, websocket, dns_rebinding
├── data/                  # Detectores de dados e serialização (5): deserialization, csv,
│                          #   mail, jwt, prototype_pollution
├── file/                  # Detectores de arquivo e dados sensíveis (3): path_traversal,
│                          #   upload, data_leak
├── httpval/               # Validadores de protocolo HTTP (7), cada um exige configuração fornecida pela aplicação
├── session/               # Segurança de sessão (2): session_guard, data_tamper
│                          #   Contorna o Engine e é usado diretamente como middleware
├── storage/               # Backends de armazenamento
│   ├── storage.go         #   Interface Backend: Incr / Get / Block / IsBlocked / Close
│   ├── memory.go          #   Memory: Mutex + map, limpeza em segundo plano a cada 30s
│   ├── file.go            #   File: persistência em JSON, flush no Close
│   └── redis/             #   Redis: submódulo separado com go.mod próprio
├── all/                   # Registro dos 27 detectores zero-configuração em uma única chamada
├── pet/                   # Mascote do projeto: SVG embutido + banner de inicialização
├── docs/
│   ├── api.md             # Referência da API
│   ├── images/            # SVGs de arquitetura / funcionalidades / ciclo de vida
│   ├── i18n/              # Documentação traduzida (12 idiomas)
│   └── superpowers/       # Especificação de design, plano de implementação, relatórios de revisão de código
└── tests/                 # Relatórios de cobertura
```

Cada pacote de detector emparelha `xxx.go` com `xxx_test.go`; o pacote `all` ainda traz testes de regressão.

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

### Configuração de segurança de sessão

O pacote `session` é usado diretamente como middleware, sem passar pelo `Engine`. O armazenamento deve ser fornecido pela aplicação (há uma implementação em memória por padrão, substituível por Redis etc.):

```go
import "github.com/erikwang2013/security-go/session"

st := session.NewMemoryStore()
defer st.Close()

tr := session.NewTracker(st)
tr.CountryOf = geo.Lookup // Opcional: integre o GeoIP para identificar logins de outros países

// Vincula a sessão após um login bem-sucedido (o token vem do seu fluxo de login)
// Detecção de login remoto: compara com as sub-redes históricas do usuário e alerta quando surge uma nova
if res := tr.Observe("user-1", r); res.Detected {
    log.Printf("[%s] %s (%v)", res.Name, res.Message, res.Details["reason"])
}
if err := tr.Issue(token, r); err != nil {      // vincula token → sub-rede de IP / UA / impressão digital do dispositivo
    http.Error(w, "session error", http.StatusInternalServerError)
    return
}

// Rota protegida: sequestro ou login remoto retorna 401 imediatamente
mux.Handle("/api/", tr.Guard(apiHandler))

// Ou apenas detecte e decida o tratamento você mesmo
if res := tr.Check(r); res.Detected {
    log.Printf("[%s] %s (%v)", res.Name, res.Message, res.Details["reason"])
}

// Logout
tr.Revoke(token)
```

Detecção de adulteração de dados: cliente e servidor compartilham uma chave; o cliente assina os parâmetros e o servidor recalcula para validar:

```go
signer := session.NewSigner(secret, storage.NewMemory()) // o segundo argumento bloqueia reenvio de assinatura, pode ser nil

sig, _ := signer.Sign(map[string]string{"amount": "100", "to": "bob"}) // cliente: enviado junto com os parâmetros

if res := signer.Verify(map[string]string{"amount": "100", "to": "bob"}, sig); res.Detected {
    log.Printf("[%s] %s (%v)", res.Name, res.Message, res.Details["reason"])
}
```

> `TrustProxyHeaders` vem desativado por padrão: `X-Forwarded-For` / `X-Real-IP` são controláveis pelo cliente; ative apenas atrás de um proxy reverso próprio.
> `FailClosed` vem desativado por padrão (libera quando o armazenamento falha, igual ao `IPBlacklist`); recomenda-se ativar em negócios sensíveis a sessão.

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

### O mascote

O pacote `pet` embute o Sentinel Gopher como SVG em tempo de compilação via `go:embed` — sem dependência de arquivo em tempo de execução e sem adicionar dependências de terceiros:

```go
import "github.com/erikwang2013/security-go/pet"

log.Println(pet.Banner())              // banner de inicialização: texto simples amigável ao terminal
http.Handle("/pet.svg", pet.Handler()) // rota de depuração: servida como image/svg+xml, cache de um dia
svg := pet.SVG()                       // ou pegue os bytes SVG brutos
```

### Documentação relacionada

- [Documentação da API](api.md) — tipos centrais, interfaces Detector/Engine, interface de backend de armazenamento, validadores HTTP
- [Especificação de design](specs/2026-07-29-attack-detection-design.md) — estrutura do pacote, diretório de detectores
- [Plano de implementação](plans/2026-07-29-attack-detection-plan.md) — plano de tarefas passo a passo e comparação de desvios de implementação
- [Relatório de revisão de código](reports/2026-07-29-code-review-report.md) — correções de bugs, cobertura de testes, avaliação de arquitetura
- [Relatório de revisão de código v2](reports/2026-07-29-code-review-report-v2.md) — Segunda passagem: 4 problemas corrigidos, 18 arquivos de teste adicionados

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
