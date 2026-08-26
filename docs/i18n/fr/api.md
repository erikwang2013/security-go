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
