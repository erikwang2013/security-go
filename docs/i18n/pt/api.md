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

## Função auxiliar

```go
// FirstMatch retorna a primeira string de padrão que casa com input; ("", false) quando nenhuma casa
func FirstMatch(input string, patterns []*regexp.Regexp) (string, bool)
```

Detectores personalizados podem reutilizar os padrões pré-compilados internos, sem recompilar as expressões regulares.

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
| `storage.NewMemory() *Memory` | Implementação em memória, `sync.Mutex` + map, limpeza automática de entradas expiradas a cada 30s |
| `storage.NewFile(path) (*File, error)` | Persistência em arquivo JSON, salvamento automático a cada 30s + flush no Close |
| `redis.New(addr, password string, db int) *Backend` | Submódulo Redis, Pipeline Incr + TTL, requer `go-redis/v9` |

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
    Load(key string) ([]byte, error)   // retorna (nil, nil) quando ausente ou expirado
    Delete(key string) error
}

session.NewMemoryStore() *MemoryStore // implementação em memória; limpa entradas expiradas a cada 30s, Close interrompe a limpeza
```

### Session

```go
type Session struct {
    IP          string    `json:"ip"`           // IP do cliente no momento da criação da sessão
    UserAgent   string    `json:"ua,omitempty"`
    Fingerprint string    `json:"fp,omitempty"` // impressão digital do dispositivo (cabeçalho X-Device-Fingerprint)
    Country     string    `json:"country,omitempty"`
    IssuedAt    time.Time `json:"issued_at"`
    LastSeen    time.Time `json:"last_seen"`    // renovada por sliding a cada Check
}
```

### Tracker

Nome do detector `session_guard` (veja `Tracker.Name()`).

```go
type Tracker struct {
    Store             Store
    TTL               time.Duration              // tempo de vida da sessão, padrão 30m, renovado por sliding a cada Check
    SubnetBits        int                        // prefixo de mesma localidade, padrão 24 (IPv6 automaticamente +24)
    CountryOf         func(ip string) string     // gancho GeoIP opcional; quando nil, a verificação de país é ignorada
    KnownNets         int                        // redes de login que o Observe mantém por usuário, padrão 8
    KnownNetTTL       time.Duration              // por quanto tempo uma rede de login é mantida, padrão 90 dias
    TokenSource       func(*http.Request) string // padrão DefaultTokenSource
    TrustProxyHeaders bool                       // padrão false
    FailClosed        bool                       // padrão false
    Failures          int                        // limite de falhas que bloqueia o token dentro da janela, padrão 5
    FailureWindow     time.Duration              // por quanto tempo as falhas são contadas; as mais antigas são ignoradas, padrão 5m
    Lockout           time.Duration              // duração do bloqueio ao cruzar o limite pela primeira vez, dobra a cada novo cruzamento, padrão 15m
    MaxLockout        time.Duration              // teto do bloqueio que dobra, padrão 24h
    BackoffWindow     time.Duration              // por quanto tempo as contagens de escalonamento são mantidas, padrão 24h
    StuffingLimit     int                        // máximo de identidades distintas que um IP pode falhar, padrão 10
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

Nome do detector `data_tamper` (veja `Signer.Name()`).

```go
type Signer struct {
    Secret  []byte           // chave HMAC compartilhada, gere com crypto/rand
    MaxSkew time.Duration    // desvio de timestamp permitido, padrão 5m
    Nonces  storage.Backend  // opcional: quando não-nil, um contador de janela bloqueia reenvio de assinatura (entre instâncias, reutilize o Redis)
}

signer := session.NewSigner(secret, mem)
sig, err := signer.Sign(map[string]string{"amount": "100", "to": "bob"}) // "<unix-ts>.<nonce>.<mac>"
res := signer.Verify(params, sig)                                        // parâmetros alterados / chave incorreta / expirado / reenvio
```

Os parâmetros são normalizados com `url.Values.Encode()` (ordenação + escape), e a ordem do map não afeta o resultado. A ordem de validação é timestamp → assinatura → contagem de nonce, portanto uma assinatura forjada não consome um nonce legítimo; com `Nonces` nulo, apenas a janela de timestamp limita o reenvio.

Valores de `Details["reason"]`: `signer_not_configured` (Critical), `signature_mismatch` (Critical), `replay` (Critical), `signature_malformed`, `timestamp_invalid`, `signature_expired`, `timestamp_in_future` (High).

## Funções auxiliares de upload de arquivo

Além de ser registrada como detector, a detecção de upload também exporta duas funções auxiliares que podem ser chamadas diretamente:

```go
// HasMaliciousExt informa se a extensão do arquivo está fora da lista de permissão (15 entradas); extensão ausente retorna true
func HasMaliciousExt(filename string) bool

// CheckExtension usa a mesma lógica, mas retorna um *Result completo (com severidade e mensagem)
func (d *MaliciousFileUpload) CheckExtension(filename string) *security.Result
```

Use-a para uma verificação prévia rápida antes de o arquivo chegar ao disco, sem construir um `Engine`.

## Mascote do projeto

O pacote `pet` embute o mascote do projeto, o Sentinel Gopher, como SVG em tempo de compilação via `go:embed`. Não adiciona nenhuma dependência de terceiros nem lê arquivos em tempo de execução:

```go
func SVG() []byte         // bytes SVG brutos; a fatia é compartilhada, o chamador não deve modificá-la
func Handler() http.Handler // servido como image/svg+xml, Cache-Control de um dia
func Banner() string      // banner em texto simples amigável ao terminal, termina com nova linha
```

```go
log.Println(pet.Banner())              // imprime na inicialização
http.Handle("/pet.svg", pet.Handler()) // monta em uma rota de depuração
```

`Handler` usa `http.ServeContent` internamente, portanto carrega `Content-Length` e suporta `Range` e `HEAD`; um `w.Write` direto ultrapassaria o buffer de sniffing de 2 KiB do `net/http` e degradaria para uma resposta chunked.

### Postura: guiada pelos resultados da detecção

O mascote não é uma imagem estática — o escudo, o radar e a lupa mudam de cor conforme a varredura, então ele serve diretamente como indicador de nível de ameaça:

```go
type Mood int

const (
    Calm     Mood = iota // a varredura não encontrou nada
    Watchful             // algo disparou, mas nada High / Critical
    Alarmed              // pelo menos um High ou Critical, exige ação
)

func MoodOf(results []*security.Result) Mood  // classificado pela ocorrência mais severa
func SVGFor(m Mood) []byte                    // arte da postura; valor desconhecido cai em Calm
func MoodHandler(moodFor func(*http.Request) Mood) http.Handler
```

`MoodOf` conta apenas resultados com `Detected` verdadeiro — um detector preenche `Severity` mesmo quando não encontra nada, então a severidade sozinha não pode disparar o alarme. A ocorrência mais severa vence, independentemente da ordem dos resultados.

Ligue o engine e você obtém uma imagem viva do estado de ameaça:

```go
e := security.NewEngine()
all.RegisterAll(e)

http.Handle("/pet.svg", pet.MoodHandler(func(r *http.Request) pet.Mood {
    return pet.MoodOf(e.DetectRequest(r))
}))
```

`MoodHandler` envia `Cache-Control: no-store` — ao contrário do `Handler` estático, sua saída muda com a varredura, e cacheá-la por um dia serviria uma postura desatualizada.

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
