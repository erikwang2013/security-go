# Security Go — Documentação da API

Este documento resume todas as APIs públicas de `security-go`: tipos centrais, interface `Detector`, registro `Engine`, interface de backend de armazenamento e construtores de validadores HTTP.

## Tipos centrais

### Result

Estrutura do resultado de detecção, retornada por cada detector:

```go
type Result struct {
    Name     string                 // Nome do detector
    Detected bool                   // Se um ataque foi detectado
    Message  string                 // Descrição do resultado
    Severity Severity               // Nível de severidade
    Details  map[string]interface{} // Detalhes adicionais
}
```

### Severity

Níveis de severidade:

```go
type Severity int

const (
    SeverityLow      Severity = iota // Baixo risco
    SeverityMedium                   // Risco médio
    SeverityHigh                     // Alto risco
    SeverityCritical                 // Crítico
)
```

## Interface Detector

Todos os detectores devem implementar esta interface:

```go
type Detector interface {
    Name() string                // Nome exclusivo do detector
    Detect(input string) *Result // Executa a detecção na entrada e retorna o resultado
}
```

## Registro Engine

`Engine` é a entrada unificada, registrando e gerenciando detectores por nome:

```go
type Engine struct { /* ... */ }

func NewEngine() *Engine                          // Cria um Engine vazio
func (e *Engine) Register(d Detector)             // Registra um detector
func (e *Engine) Detect(name, input string) *Result // Detecta uma única entrada por nome
func (e *Engine) DetectAll(input string) []*Result  // Detecção completa (retorna apenas Detected=true)
func (e *Engine) DetectRequest(r *http.Request) []*Result // Detecta uma requisição HTTP completa
```

`DetectRequest` coleta automaticamente URL, Query, Headers e Cookies da requisição como entrada. Cada entrada é reescaneada após decodificação de URL, então cargas codificadas como `%3Cscript%3E` não conseguem contornar a detecção.

## Ponto de entrada de registro

```go
// O pacote all fornece registro de uma só vez de todos os detectores zero-configuração (27)
all.RegisterAll(engine)
```

## Interface de backend de armazenamento

`httpval.IPBlacklist` usa armazenamento plugável por meio desta interface:

```go
type Backend interface {
    Incr(key string, window time.Duration) (int, error)   // Incrementa a contagem na janela +1
    Get(key string) (int, error)                          // Lê a contagem
    Block(key string, duration time.Duration) error       // Bloqueia por um período determinado
    IsBlocked(key string) (bool, error)                   // Se está bloqueado
    Close() error                                         // Fecha e libera recursos
}
```

Implementações:

| Backend | Descrição |
|------|------|
| `storage.NewMemory()` | Implementação em memória, `sync.Mutex` + map, limpeza automática de entradas expiradas a cada 30s |
| `storage.NewFile(path)` | Persistência em arquivo JSON, salvamento automático a cada 30s + flush no Close |
| `storage/redis` | Submódulo Redis, Pipeline Incr + TTL, requer `go-redis/v9` |

## Validadores HTTP

```go
// Validação de lista de permissão de métodos HTTP
e.Register(&httpval.Method{})

// Limite de tamanho do corpo da requisição (padrão 10MB)
e.Register(httpval.NewBodySize(5 * 1024 * 1024)) // 5MB

// Lista de permissão de Content-Type (lista vazia = recusar todos)
e.Register(httpval.NewContentType([]string{
    "application/json", "application/x-www-form-urlencoded",
}))

// Validação de origem CSRF (verifica se Origin corresponde ao Host em requisições cross-origin)
e.Register(&httpval.CSRFOrigin{
    Host: "example.com", AllowList: []string{"api.example.com"},
})

// Blacklist de IP (banimento automático após N ataques na janela, padrão 5 vezes/60s → banimento de 15 min)
bl := httpval.NewIPBlacklist(mem) // mem é qualquer implementação de storage.Backend
e.Register(bl)
blocked, _ := bl.RecordAttack(clientIP)
```

### Profundidade de aninhamento JSON e atributos de cookie

| Construtor | Descrição |
|--------|------|
| `NewNestedDepth(maxDepth, maxKeys) *NestedDepth` | Analisa um corpo JSON em streaming: reporta `nested_depth` ao exceder a profundidade (padrão 32) ou o número de elementos. JSON inválido ou truncado nunca corresponde |
| `NewCookieAttrs(requireSecure, requireHttpOnly, requireSameSite) *CookieAttrs` | Valida um `Set-Cookie`: atributos ausentes, valor longo demais (`MaxValueLen`), valor vazio (`RequireNonEmpty`) |

## Segurança de sessão

O pacote `session` detecta **sequestro do cliente**, **adulteração de dados** e **login remoto**. Ele precisa do `*http.Request` completo (token, IP do cliente, User-Agent) e de armazenamento e chave fornecidos pela aplicação, por isso não é registrado no `Engine`, sendo chamado diretamente como middleware/função.

### Interface Store

A vinculação de sessão não pode ser expressa com `storage.Backend` (apenas contagem e bloqueio), então `session` traz uma interface pequena própria:

```go
type Store interface {
    Save(key string, value []byte, ttl time.Duration) error
    Load(key string) ([]byte, error)   // 不存在或已过期返回 (nil, nil)
    Delete(key string) error
}

session.NewMemoryStore() *MemoryStore // 内存实现，30s 清理过期条目，Close 停止清理
```

### Session

```go
type Session struct {
    IP          string    `json:"ip"`           // 建立会话时的客户端 IP
    UserAgent   string    `json:"ua,omitempty"`
    Fingerprint string    `json:"fp,omitempty"` // 设备指纹（X-Device-Fingerprint 头）
    Country     string    `json:"country,omitempty"`
    IssuedAt    time.Time `json:"issued_at"`
    LastSeen    time.Time `json:"last_seen"`    // 每次 Check 滑动续期
}
```

### Tracker

```go
type Tracker struct {
    Store             Store
    TTL               time.Duration              // 会话生命周期，默认 30m，每次 Check 滑动续期
    SubnetBits        int                        // 同地判定前缀，默认 24（IPv6 自动 +24）
    CountryOf         func(ip string) string     // 可选 GeoIP 钩子；为 nil 时跳过国家判定
    KnownNets         int                        // Observe 每用户保留的登录网段数，默认 8
    KnownNetTTL       time.Duration              // 登录网段保留时长，默认 90 天
    TokenSource       func(*http.Request) string // 默认 DefaultTokenSource
    TrustProxyHeaders bool                       // 默认 false
    FailClosed        bool                       // 默认 false
    MaxLockout        time.Duration              // 每次锁定翻倍的上限，默认 24h
    BackoffWindow     time.Duration              // 升级计数的保留时长，默认 24h
    StuffingLimit     int                        // 同一 IP 允许失败的不同身份数上限，默认 10
}
```

| Método | Descrição |
|------|------|
| `NewTracker(store) *Tracker` | Cria e preenche os valores padrão |
| `Issue(token, r) error` | Após login bem-sucedido, vincula token → sub-rede IP / UA / impressão digital; token vazio retorna erro |
| `Check(r) *Result` | Valida a cada requisição; se detectar, retorna `Detected: true`; ao passar, renova por sliding |
| `Observe(user, r) *Result` | No login, compara com as faixas de rede históricas do usuário e alerta quando surge uma nova; o primeiro login não tem linha de base e não alerta |
| `Guard(http.Handler) http.Handler` | Wrapper de middleware; se `Check` detectar, retorna 401 |
| `Revoke(token) error` | Logout; a sessão é invalidada imediatamente |
| `DefaultTokenSource(r) string` | Obtém `Authorization: Bearer <token>`, senão o Cookie `session` |
| `RecordFailure(identity, r) error` | Conta um login falho (identity é a chave de autenticação, como o usuário; r fornece o IP do cliente). Ao atingir `Failures` (padrão 5 em 5 minutos) bloqueia a identidade, dobrando a cada vez até `MaxLockout` (padrão 24 h) |
| `CheckLogin(identity, r) *Result` | Verificação prévia da tentativa: `token_locked` se a identidade está bloqueada, `credential_stuffing` se o IP já falhou contra `StuffingLimit` (padrão 10) identidades distintas — ambos Critical |
| `GuardLogin(next, identity) http.Handler` | Middleware para o endpoint de autenticação: 429 com `Retry-After` ao disparar; depois do handler um 401 conta como falha e um 2xx zera o contador |
| `IsLocked(token) (bool, time.Time)` | Se o token está bloqueado e até quando; um erro do armazenamento é lido como não bloqueado |
| `ClearFailures(token) error` | Zera o contador de falhas após um login bem-sucedido (o bloqueio corre pelo próprio temporizador) |

Valores de `Details["reason"]`:

| reason | Condição de disparo | Severidade |
|--------|---------|---------|
| `missing_token` | A requisição não traz token | High |
| `unknown_token` | token não emitido, já `Revoke`ado ou expirado | High |
| `token_locked` | Limite de falhas atingido dentro da janela, token bloqueado | Critical |
| `credential_stuffing` | Um IP falhou contra `StuffingLimit` identidades distintas dentro da janela | Critical |
| `client_hijack` | Mudança de UA ou de impressão digital do dispositivo | Critical |
| `remote_login` | `CountryOf` determina outro país (Critical) / outra sub-rede de IP (High); compartilhado por `Check` e `Observe` | Critical / High |
| `store_error` | Falha de leitura do armazenamento com `FailClosed = true` | High |

> `TrustProxyHeaders` vem desativado por padrão: `X-Forwarded-For` / `X-Real-IP` são controláveis pelo cliente; se ativado, o sequestrador pode forjar o IP vinculado. Ative apenas atrás de um proxy reverso próprio.
> `FailClosed` vem desativado por padrão (libera quando o armazenamento falha), igual ao `httpval.IPBlacklist`. A chave de armazenamento é o SHA-256 do token, então o vazamento do armazenamento não entrega diretamente um token utilizável.

### Signer

```go
type Signer struct {
    Secret  []byte           // 共享 HMAC 密钥，用 crypto/rand 生成
    MaxSkew time.Duration    // 时间戳允许偏差，默认 5m
    Nonces  storage.Backend  // 可选：非空时用窗口计数拦截签名重放（可跨实例，复用 Redis）
}

signer := session.NewSigner(secret, mem)
sig, err := signer.Sign(map[string]string{"amount": "100", "to": "bob"}) // "<unix-ts>.<nonce>.<mac>"
res := signer.Verify(params, sig)                                        // 参数被改动/密钥不符/超时/重放
```

Os parâmetros são normalizados com `url.Values.Encode()` (ordenação + escape), e a ordem do map não afeta o resultado. A ordem de validação é timestamp → assinatura → contagem de nonce, portanto uma assinatura forjada não consome um nonce legítimo; com `Nonces` nulo, apenas a janela de timestamp limita o reenvio.

Valores de `Details["reason"]`: `signer_not_configured` (Critical), `signature_mismatch` (Critical), `replay` (Critical), `signature_malformed`, `timestamp_invalid`, `signature_expired`, `timestamp_in_future` (High).

## Exemplo de detector personalizado

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

---

Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
