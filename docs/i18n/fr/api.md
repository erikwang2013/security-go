# Security Go — Documentation de l'API

Ce document récapitule toutes les interfaces publiques de `security-go` : les types principaux, l'interface `Detector`, le registre `Engine`, l'interface des backends de stockage et les constructeurs de validateurs HTTP.

## Types principaux

### Result

Structure de résultat de détection, renvoyée par chaque détecteur :

```go
type Result struct {
    Name     string                 // Nom du détecteur
    Detected bool                   // Indique si une attaque a été détectée
    Message  string                 // Description du résultat
    Severity Severity               // Niveau de gravité
    Details  map[string]interface{} // Détails supplémentaires
}
```

### Severity

Niveaux de gravité :

```go
type Severity int

const (
    SeverityLow      Severity = iota // Risque faible
    SeverityMedium                   // Risque moyen
    SeverityHigh                     // Risque élevé
    SeverityCritical                 // Critique
)
```

## Interface Detector

Tous les détecteurs doivent implémenter cette interface :

```go
type Detector interface {
    Name() string                // Nom unique du détecteur
    Detect(input string) *Result // Exécute la détection sur l'entrée, renvoie le résultat
}
```

## Registre Engine

`Engine` est le point d'entrée unifié qui enregistre et gère les détecteurs par nom :

```go
type Engine struct { /* ... */ }

func NewEngine() *Engine                          // Crée un Engine vide
func (e *Engine) Register(d Detector)             // Enregistre un détecteur
func (e *Engine) Detect(name, input string) *Result // Détecte une seule entrée par nom
func (e *Engine) DetectAll(input string) []*Result  // Détection complète (renvoie uniquement Detected=true)
func (e *Engine) DetectRequest(r *http.Request) []*Result // Détecte une requête HTTP complète
```

`DetectRequest` collecte automatiquement l'URL, la Query, les Headers et les Cookies de la requête comme entrées.

## Point d'enregistrement

```go
// Le paquet all fournit l'enregistrement en une fois de tous les détecteurs sans configuration (27)
all.RegisterAll(engine)
```

## Interface des backends de stockage

`httpval.IPBlacklist` utilise le stockage enfichable via cette interface :

```go
type Backend interface {
    Incr(key string, window time.Duration) (int, error)   // Incrémente le compteur de la fenêtre de 1
    Get(key string) (int, error)                          // Lit le compteur
    Block(key string, duration time.Duration) error       // Bannit pendant une durée donnée
    IsBlocked(key string) (bool, error)                   // Vérifie si la clé est bannie
    Close() error                                         // Ferme et libère les ressources
}
```

Implémentations :

| Backend | Description |
|------|------|
| `storage.NewMemory()` | Implémentation en mémoire, `sync.Mutex` + map, nettoyage automatique des entrées expirées toutes les 30 s |
| `storage.NewFile(path)` | Persistance dans un fichier JSON, sauvegarde automatique toutes les 30 s + flush à la fermeture |
| `storage/redis` | Sous-module Redis, Pipeline Incr + TTL, nécessite `go-redis/v9` |

## Validateurs HTTP

```go
// Validation de la liste blanche des méthodes HTTP
e.Register(&httpval.Method{})

// Limite de taille du corps (10 Mo par défaut)
e.Register(httpval.NewBodySize(5 * 1024 * 1024)) // 5 Mo

// Liste blanche Content-Type (liste vide = refuser tout)
e.Register(httpval.NewContentType([]string{
    "application/json", "application/x-www-form-urlencoded",
}))

// Validation de l'Origin CSRF (les requêtes cross-origin doivent correspondre au Host)
e.Register(&httpval.CSRFOrigin{
    Host: "example.com", AllowList: []string{"api.example.com"},
})

// Liste noire IP (bannissement automatique après N attaques dans la fenêtre, par défaut 5/60 s → bannissement 15 min)
bl := httpval.NewIPBlacklist(mem) // mem est n'importe quelle implémentation de storage.Backend
e.Register(bl)
blocked, _ := bl.RecordAttack(clientIP)
```

### Profondeur d'imbrication JSON et attributs de cookie

| Constructeur | Description |
|--------|------|
| `NewNestedDepth(maxDepth, maxKeys) *NestedDepth` | Analyse en flux un corps JSON : signale `nested_depth` dès que la profondeur (par défaut 32) ou le nombre d'éléments est dépassé. Un JSON invalide ou tronqué ne correspond jamais |
| `NewCookieAttrs(requireSecure, requireHttpOnly, requireSameSite) *CookieAttrs` | Valide un `Set-Cookie` : attributs manquants, valeur trop longue (`MaxValueLen`), valeur vide (`RequireNonEmpty`) |

## Sécurité de session

Le paquet `session` détecte le **détournement du client**, la **falsification de données** et la **connexion distante**. Il a besoin du `*http.Request` complet (token, IP client, User-Agent) ainsi que du stockage et de la clé fournis par l'application ; il n'est donc pas enregistré dans `Engine` et s'appelle directement comme middleware/fonction.

### Interface Store

La liaison de session ne peut pas être exprimée avec `storage.Backend` (qui ne gère que le comptage et le bannissement), `session` fournit donc sa propre petite interface :

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
}
```

| Méthode | Description |
|------|------|
| `NewTracker(store) *Tracker` | Crée et remplit les valeurs par défaut |
| `Issue(token, r) error` | Après une connexion réussie, lie token → sous-réseau IP / UA / empreinte ; un token vide renvoie une erreur |
| `Check(r) *Result` | Vérifie à chaque requête, renvoie `Detected: true` en cas de correspondance ; renouvelle par glissement si la vérification passe |
| `Observe(user, r) *Result` | Compare les sous-réseaux de connexion historiques de l'utilisateur lors de la connexion, alerte si un nouveau sous-réseau apparaît ; aucune alerte à la première connexion faute de référence |
| `Guard(http.Handler) http.Handler` | Enveloppe middleware, renvoie 401 dès que `Check` correspond |
| `Revoke(token) error` | Déconnexion, la session est immédiatement invalidée |
| `DefaultTokenSource(r) string` | Récupère `Authorization: Bearer <token>`, sinon le Cookie `session` |
| `RecordFailure(token) error` | Compte une authentification échouée ; à l'atteinte de `Failures` (par défaut 5 en 5 minutes) un verrou est écrit, `Lockout` par défaut 15 minutes |
| `IsLocked(token) (bool, time.Time)` | Indique si le jeton est verrouillé et jusqu'à quand ; une erreur de stockage est lue comme non verrouillé |
| `ClearFailures(token) error` | Remet à zéro le compteur d'échecs après une connexion réussie (le verrou suit son propre minuteur) |

Valeurs de `Details["reason"]` :

| reason | Condition de déclenchement | Niveau de gravité |
|--------|---------|---------|
| `missing_token` | La requête ne porte pas de token | High |
| `unknown_token` | token non émis, déjà `Revoke` ou expiré | High |
| `token_locked` | Seuil d'échecs atteint dans la fenêtre, jeton verrouillé | Critical |
| `client_hijack` | Changement d'UA ou d'empreinte d'appareil | Critical |
| `remote_login` | `CountryOf` détecte un changement de pays (Critical) / de sous-réseau IP (High), partagé par `Check` et `Observe` | Critical / High |
| `store_error` | Échec de lecture du stockage et `FailClosed = true` | High |

> `TrustProxyHeaders` est désactivé par défaut : `X-Forwarded-For` / `X-Real-IP` sont contrôlables par le client ; une fois activés, un attaquant peut falsifier l'IP liée. Ne l'activez qu'après un reverse proxy dédié.
> `FailClosed` est désactivé par défaut (passage en cas de panne de stockage), comme pour `httpval.IPBlacklist`. La clé de stockage est le SHA-256 du token ; une fuite du stockage ne donne pas directement un token utilisable.

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

Les paramètres sont normalisés avec `url.Values.Encode()` (tri + échappement), l'ordre du map n'affecte pas le résultat. L'ordre de vérification est horodatage → signature → compteur de nonce ; une signature falsifiée ne peut donc pas consommer un nonce légitime. Lorsque `Nonces` est nil, seule la fenêtre d'horodatage limite la relecture.

Valeurs de `Details["reason"]` : `signer_not_configured` (Critical), `signature_mismatch` (Critical), `replay` (Critical), `signature_malformed`, `timestamp_invalid`, `signature_expired`, `timestamp_in_future` (High).

## Exemple de détecteur personnalisé

```go
type MyDetector struct{}

func (d *MyDetector) Name() string { return "my_detector" }

func (d *MyDetector) Detect(input string) *security.Result {
    return &security.Result{
        Name: "my_detector", Detected: strings.Contains(input, "evil"),
        Severity: security.SeverityHigh, Message: "contenu malveillant détecté",
    }
}

e.Register(&MyDetector{})
```

---

Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
