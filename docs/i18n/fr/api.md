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

`DetectRequest` collecte automatiquement l'URL, la Query, les Headers et les Cookies de la requête comme entrées. Chaque entrée est également analysée après décodage d'URL : une charge encodée comme `%3Cscript%3E` ne peut donc pas contourner la détection.

## Point d'enregistrement

```go
// Le paquet all fournit l'enregistrement en une fois de tous les détecteurs sans configuration (27)
all.RegisterAll(engine)
```

## Fonctions utilitaires

```go
// FirstMatch renvoie la première chaîne de motif qui correspond à input ; si aucune ne correspond, renvoie ("", false)
func FirstMatch(input string, patterns []*regexp.Regexp) (string, bool)
```

Permet aux détecteurs personnalisés de réutiliser les motifs précompilés intégrés, sans recompiler les expressions régulières.

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
| `storage.NewMemory() *Memory` | Implémentation en mémoire, `sync.Mutex` + map, nettoyage automatique des entrées expirées toutes les 30 s |
| `storage.NewFile(path) (*File, error)` | Persistance dans un fichier JSON, sauvegarde automatique toutes les 30 s + flush à la fermeture |
| `redis.New(addr, password string, db int) *Backend` | Sous-module Redis, Pipeline Incr + TTL, nécessite `go-redis/v9` |

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
    Load(key string) ([]byte, error)   // Renvoie (nil, nil) si absent ou expiré
    Delete(key string) error
}

session.NewMemoryStore() *MemoryStore // Implémentation en mémoire, purge des entrées expirées toutes les 30 s, Close arrête la purge
```

### Session

```go
type Session struct {
    IP          string    `json:"ip"`           // IP du client à l'établissement de la session
    UserAgent   string    `json:"ua,omitempty"`
    Fingerprint string    `json:"fp,omitempty"` // Empreinte de l'appareil (en-tête X-Device-Fingerprint)
    Country     string    `json:"country,omitempty"`
    IssuedAt    time.Time `json:"issued_at"`
    LastSeen    time.Time `json:"last_seen"`    // Renouvellement glissant à chaque Check
}
```

### Tracker

Nom du détecteur `session_guard` (voir `Tracker.Name()`).

```go
type Tracker struct {
    Store             Store
    TTL               time.Duration              // Durée de vie de la session, 30m par défaut, renouvelée par glissement à chaque Check
    SubnetBits        int                        // Préfixe de détermination du même lieu, 24 par défaut (+24 automatique en IPv6)
    CountryOf         func(ip string) string     // Hook GeoIP facultatif ; si nil, le contrôle du pays est ignoré
    KnownNets         int                        // Nombre de sous-réseaux de connexion conservés par utilisateur par Observe, 8 par défaut
    KnownNetTTL       time.Duration              // Durée de conservation des sous-réseaux de connexion, 90 jours par défaut
    TokenSource       func(*http.Request) string // DefaultTokenSource par défaut
    TrustProxyHeaders bool                       // false par défaut
    FailClosed        bool                       // false par défaut
    Failures          int                        // Seuil d'échecs verrouillant le token dans la fenêtre, 5 par défaut
    FailureWindow     time.Duration              // Durée de conservation du compteur d'échecs, au-delà non compté, 5m par défaut
    Lockout           time.Duration              // Durée du verrouillage au premier franchissement du seuil, doublée à chaque fois, 15m par défaut
    MaxLockout        time.Duration              // Plafond du doublement à chaque verrouillage, 24h par défaut
    BackoffWindow     time.Duration              // Durée de conservation du compteur d'escalade, 24h par défaut
    StuffingLimit     int                        // Nombre maximal d'identités distinctes en échec pour une même IP, 10 par défaut
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
| `RecordFailure(identity, r) error` | Compte un échec de connexion (identity est la clé d'authentification, par ex. l'identifiant ; r fournit l'IP du client). À l'atteinte de `Failures` (par défaut 5 en 5 minutes) l'identité est verrouillée, chaque verrou doublant jusqu'à `MaxLockout` (par défaut 24 h) |
| `CheckLogin(identity, r) *Result` | Contrôle préalable d'une tentative : `token_locked` si l'identité est verrouillée, `credential_stuffing` si l'IP a déjà échoué contre `StuffingLimit` (par défaut 10) identités distinctes — les deux en Critical |
| `GuardLogin(next, identity) http.Handler` | Middleware pour un point d'authentification : 429 avec `Retry-After` en cas de déclenchement ; ensuite un 401 compte comme échec et un 2xx remet le compteur à zéro |
| `IsLocked(token) (bool, time.Time)` | Indique si le jeton est verrouillé et jusqu'à quand ; une erreur de stockage est lue comme non verrouillé |
| `ClearFailures(token) error` | Remet à zéro le compteur d'échecs après une connexion réussie (le verrou suit son propre minuteur) |

Valeurs de `Details["reason"]` :

| reason | Condition de déclenchement | Niveau de gravité |
|--------|---------|---------|
| `missing_token` | La requête ne porte pas de token | High |
| `unknown_token` | token non émis, déjà `Revoke` ou expiré | High |
| `token_locked` | Seuil d'échecs atteint dans la fenêtre, jeton verrouillé | Critical |
| `credential_stuffing` | Une IP a échoué contre `StuffingLimit` identités distinctes dans la fenêtre | Critical |
| `client_hijack` | Changement d'UA ou d'empreinte d'appareil | Critical |
| `remote_login` | `CountryOf` détecte un changement de pays (Critical) / de sous-réseau IP (High), partagé par `Check` et `Observe` | Critical / High |
| `store_error` | Échec de lecture du stockage et `FailClosed = true` | High |

> `TrustProxyHeaders` est désactivé par défaut : `X-Forwarded-For` / `X-Real-IP` sont contrôlables par le client ; une fois activés, un attaquant peut falsifier l'IP liée. Ne l'activez qu'après un reverse proxy dédié.
> `FailClosed` est désactivé par défaut (passage en cas de panne de stockage), comme pour `httpval.IPBlacklist`. La clé de stockage est le SHA-256 du token ; une fuite du stockage ne donne pas directement un token utilisable.

### Signer

Nom du détecteur `data_tamper` (voir `Signer.Name()`).

```go
type Signer struct {
    Secret  []byte           // Clé HMAC partagée, à générer avec crypto/rand
    MaxSkew time.Duration    // Écart d'horodatage autorisé, 5m par défaut
    Nonces  storage.Backend  // Facultatif : si non nil, un compteur à fenêtre bloque la relecture des signatures (inter-instances possible, réutilise Redis)
}

signer := session.NewSigner(secret, mem)
sig, err := signer.Sign(map[string]string{"amount": "100", "to": "bob"}) // "<unix-ts>.<nonce>.<mac>"
res := signer.Verify(params, sig)                                        // Paramètres modifiés / clé incorrecte / délai dépassé / relecture
```

Les paramètres sont normalisés avec `url.Values.Encode()` (tri + échappement), l'ordre du map n'affecte pas le résultat. L'ordre de vérification est horodatage → signature → compteur de nonce ; une signature falsifiée ne peut donc pas consommer un nonce légitime. Lorsque `Nonces` est nil, seule la fenêtre d'horodatage limite la relecture.

Valeurs de `Details["reason"]` : `signer_not_configured` (Critical), `signature_mismatch` (Critical), `replay` (Critical), `signature_malformed`, `timestamp_invalid`, `signature_expired`, `timestamp_in_future` (High).

## Fonctions utilitaires d'upload de fichiers

Outre son enregistrement comme détecteur, la détection d'upload exporte deux fonctions utilitaires directement appelables :

```go
// HasMaliciousExt indique si l'extension du nom de fichier est hors de la liste blanche (15 extensions) ; true si aucune extension
func HasMaliciousExt(filename string) bool

// CheckExtension a la même origine que ci-dessus, mais renvoie un *Result complet (avec gravité et description)
func (d *MaliciousFileUpload) CheckExtension(filename string) *security.Result
```

Pour une vérification préalable rapide avant l'écriture du fichier sur disque, sans construire d'`Engine`.

## Mascotte du projet

Le paquet `pet` intègre au moment de la compilation le SVG de la mascotte du projet, Sentinel Gopher, via `go:embed` : aucune dépendance tierce, aucune lecture de fichier à l'exécution :

```go
func SVG() []byte         // Octets SVG bruts ; le slice est partagé, l'appelant ne doit pas le modifier
func Handler() http.Handler // Servi en image/svg+xml, Cache-Control d'un jour
func Banner() string      // Bannière en texte brut adaptée au terminal, avec saut de ligne final
```

```go
log.Println(pet.Banner())              // Imprimé au démarrage
http.Handle("/pet.svg", pet.Handler()) // Monté sur une route de débogage
```

En interne, `Handler` passe par `http.ServeContent` : il porte donc `Content-Length` et prend en charge `Range` et `HEAD` ; un `w.Write` direct dépasserait le tampon d'analyse de 2 Kio de `net/http` et dégénérerait en réponse chunked.

### Humeur : pilotée par les résultats de détection

La mascotte n'est pas une image statique — son bouclier, son radar et sa loupe changent de couleur selon le résultat de l'analyse, et servent directement d'indicateur de niveau de menace :

```go
type Mood int

const (
    Calm     Mood = iota // analyse sans correspondance
    Watchful             // correspondances, mais aucune High / Critical
    Alarmed              // au moins un High ou Critical, à traiter
)

func MoodOf(results []*security.Result) Mood  // classe selon la correspondance la plus grave
func SVGFor(m Mood) []byte                    // le visuel de cette humeur ; une valeur inconnue retombe sur Calm
func MoodHandler(moodFor func(*http.Request) Mood) http.Handler
```

`MoodOf` ne compte que les résultats dont `Detected` est vrai — un détecteur porte un `Severity` même sans correspondance, la gravité seule ne doit donc pas déclencher l'alarme. Plus la correspondance est grave, plus elle est prioritaire, indépendamment de l'ordre des résultats.

Reliez le moteur et vous obtenez une carte d'état de menace vivante :

```go
e := security.NewEngine()
all.RegisterAll(e)

http.Handle("/pet.svg", pet.MoodHandler(func(r *http.Request) pet.Mood {
    return pet.MoodOf(e.DetectRequest(r))
}))
```

`MoodHandler` envoie `Cache-Control: no-store` — contrairement au `Handler` statique, sa sortie change avec le résultat de l'analyse ; la mettre en cache un jour renverrait une posture périmée.

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
