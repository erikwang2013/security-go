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

`DetectRequest` coleta automaticamente URL, Query, Headers e Cookies da requisição como entrada.

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
