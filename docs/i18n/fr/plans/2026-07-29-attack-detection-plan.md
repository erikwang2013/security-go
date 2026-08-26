# Attack Detection Package — Plan de mise en œuvre

> **Pour les agents automatisés :** SOUS-COMPÉTENCE REQUISE : utilisez superpowers:subagent-driven-development (recommandé) ou superpowers:executing-plans pour implémenter ce plan tâche par tâche.

**Objectif :** Créer une bibliothèque de détection d'attaques en Go pur avec 32 détecteurs répartis sur 5 catégories, 3 backends de stockage enfichables et un registre Engine unifié. **Statut : Terminé (2026-07-29).**

**Architecture :** Conception à interface plate — chaque détecteur implémente `Detector` (Name + Detect). Motifs regex précompilés. Engine fournit le registre, la recherche par nom et `DetectRequest` pour l'analyse de requêtes HTTP complètes. RegisterAll se trouve dans `all/all.go` (paquet séparé).

**Pile technique :** Go 1.21+, `regexp` de la bibliothèque standard + `net/http`, `go-redis` pour le backend Redis (sous-module optionnel dans `storage/redis/`).

---

### Tâche 1 : Initialiser le module Go et les types principaux

**Fichiers :**
- Créer : `go.mod`
- Créer : `security.go`

- [x] **Étape 1 : Initialiser le module Go**

```bash
cd /home/wwwroot/bag/security-go && go mod init github.com/erikwang2013/security-go
```

- [x] **Étape 2 : Créer security.go — Result, Severity, Detector interface, Engine**

```go
package security

import "net/http"

type Severity int

const (
	SeverityLow Severity = iota
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

type Result struct {
	Name     string
	Detected bool
	Message  string
	Severity Severity
	Details  map[string]interface{}
}

type Detector interface {
	Name() string
	Detect(input string) *Result
}

type Engine struct {
	detectors map[string]Detector
}

func NewEngine() *Engine {
	return &Engine{detectors: make(map[string]Detector)}
}

func (e *Engine) Register(d Detector) {
	e.detectors[d.Name()] = d
}

func (e *Engine) Detect(name, input string) *Result {
	if d, ok := e.detectors[name]; ok {
		return d.Detect(input)
	}
	return nil
}

func (e *Engine) DetectAll(input string) []*Result {
	var results []*Result
	for _, d := range e.detectors {
		if r := d.Detect(input); r != nil && r.Detected {
			results = append(results, r)
		}
	}
	return results
}

func (e *Engine) DetectRequest(r *http.Request) []*Result {
	var results []*Result
	inputs := collectRequestInputs(r)
	for _, input := range inputs {
		results = append(results, e.DetectAll(input)...)
	}
	return results
}

func collectRequestInputs(r *http.Request) []string {
	var inputs []string
	inputs = append(inputs, r.URL.String())
	inputs = append(inputs, r.URL.Query().Encode())
	for key, vals := range r.Header {
		for _, v := range vals {
			inputs = append(inputs, key+": "+v)
		}
	}
	for _, c := range r.Cookies() {
		inputs = append(inputs, c.Name+"="+c.Value)
	}
	return inputs
}
```

- [x] **Étape 3 : Compiler** — `go build ./...`
- [x] **Étape 4 : Valider** — `feat: initialize Go module with core types and Engine`

---

### Tâche 2 : Interface des backends de stockage et Memory

**Fichiers :**
- Créer : `storage/storage.go`
- Créer : `storage/memory.go`

- [x] **Étape 1 : storage/storage.go** — Interface Backend (Incr, Get, Block, IsBlocked, Close)
- [x] **Étape 2 : storage/memory.go** — Implémentation basée sur sync.Map avec goroutine de nettoyage TTL
- [x] **Étape 3 : Compiler** — `go build ./storage/...`
- [x] **Étape 4 : Valider** — `feat: add storage interface and memory backend`

---

### Tâche 3 : Stockage File et Redis

**Fichiers :**
- Créer : `storage/file.go`
- Créer : `storage/redis.go`
- Modifier : `go.mod` (ajouter la dépendance go-redis)

- [x] **Étape 1 : storage/file.go** — Persistance dans un fichier JSON avec flush différé
- [x] **Étape 2 : storage/redis.go** — Backend Redis utilisant go-redis/v9
- [x] **Étape 3 : Compiler** — `go build ./storage/...`
- [x] **Étape 4 : Valider** — `feat: add file and redis storage backends`

---

### Tâche 4 : Détecteurs d'injection — XSS, SQL

**Fichiers :**
- Créer : `injection/xss.go`
- Créer : `injection/sql.go`

- [x] **Étape 1 : injection/xss.go** — Motifs `<script>`, `on[a-z]+=`, `javascript:`, SVG/CSS
- [x] **Étape 2 : injection/sql.go** — UNION SELECT (avec contournement `/**/`), sleep/benchmark, aveugle booléen, énumération de schéma, procédure stockée
- [x] **Étape 3 : Compiler** — `go build ./injection/...`
- [x] **Étape 4 : Valider** — `feat: add XSS and SQL injection detectors`

---

### Tâche 5 : Détecteurs d'injection — Command, NoSQL, LDAP, XPATH

**Fichiers :**
- Créer : `injection/command.go`
- Créer : `injection/nosql.go`
- Créer : `injection/ldap.go`
- Créer : `injection/xpath.go`

- [x] **Étape 1 : injection/command.go** — accent grave, `$()`, tube, `/dev/tcp`, fonctions d'exécution PHP
- [x] **Étape 2 : injection/nosql.go** — MongoDB `$ne`/`$gt`/`$regex`/`$where`, contournement d'authentification
- [x] **Étape 3 : injection/ldap.go** — opérateurs de filtre `(`, `)`, `&`, `\|`, `*`
- [x] **Étape 4 : injection/xpath.go** — contournement booléen, string-length, count
- [x] **Étape 5 : Compiler et valider**

---

### Tâche 6 : Détecteurs d'injection — JNDI, SSI, GraphQL, SSTI

**Fichiers :**
- Créer : `injection/jndi.go`
- Créer : `injection/ssi.go`
- Créer : `injection/graphql.go`
- Créer : `injection/ssti.go`

- [x] **Étape 1 : injection/jndi.go** — `${jndi:ldap://`, `${lower:j}`, `${env:}`, protocoles rmi/dns
- [x] **Étape 2 : injection/ssi.go** — `<!--#exec`, `<!--#include`, `<!--#echo`
- [x] **Étape 3 : injection/graphql.go** — `__schema`, `__type`, requête imbriquée profonde, mutation
- [x] **Étape 4 : injection/ssti.go** — Jinja2 `{{}}`, FreeMarker `${}`, ERB `<% %>`, MRO Python
- [x] **Étape 5 : Compiler et valider**

---

### Tâche 7 : Détecteurs de protocole — SSRF, XXE, Injection d'en-tête

**Fichiers :**
- Créer : `protocol/ssrf.go`
- Créer : `protocol/xxe.go`
- Créer : `protocol/header_injection.go`

- [x] **Étape 1 : protocol/ssrf.go** — IP interne, 169.254.169.254, loopback IPv6, gopher/dict
- [x] **Étape 2 : protocol/xxe.go** — `<!ENTITY SYSTEM/PUBLIC`, entités paramétrées, DOCTYPE
- [x] **Étape 3 : protocol/header_injection.go** — CRLF, injection Set-Cookie/Location
- [x] **Étape 4 : Compiler et valider**

---

### Tâche 8 : Détecteurs de protocole — Host Header, Request Smuggling, Open Redirect, CORS, WebSocket, DNS Rebinding

**Fichiers :**
- Créer : `protocol/host_header.go`
- Créer : `protocol/request_smuggling.go`
- Créer : `protocol/open_redirect.go`
- Créer : `protocol/cors.go`
- Créer : `protocol/websocket.go`
- Créer : `protocol/dns_rebinding.go`

- [x] **Étape 1 : les 6 détecteurs de protocole** — un fichier chacun, motifs regex précompilés
- [x] **Étape 2 : Compiler et valider**

---

### Tâche 9 : Détecteurs de validation HTTP

**Fichiers :**
- Créer : `httpval/method.go`
- Créer : `httpval/body_size.go`
- Créer : `httpval/content_type.go`
- Créer : `httpval/csrf_origin.go`
- Créer : `httpval/ip_blacklist.go`

- [x] **Étape 1 : httpval/method.go** — liste blanche GET/POST/PUT/DELETE/HEAD/OPTIONS/PATCH
- [x] **Étape 2 : httpval/body_size.go** — vérification de taille maximale, 10 Mo par défaut
- [x] **Étape 3 : httpval/content_type.go** — liste blanche MIME
- [x] **Étape 4 : httpval/csrf_origin.go** — correspondance Origin cross-origin vs Host
- [x] **Étape 5 : httpval/ip_blacklist.go** — limitation de débit par fenêtre (5/60 s → bannissement 15 min), utilise storage.Backend
- [x] **Étape 6 : Compiler et valider**

---

### Tâche 10 : Détecteurs de données/sérialisation

**Fichiers :**
- Créer : `data/deserialization.go`
- Créer : `data/csv_injection.go`
- Créer : `data/mail_header.go`
- Créer : `data/jwt_attack.go`
- Créer : `data/prototype_pollution.go`

- [x] **Étape 1 : data/deserialization.go** — PHP `O:nombre:`, `C:nombre:`, unserialize(), méthodes magiques
- [x] **Étape 2 : data/csv_injection.go** — préfixes de formule `=cmd|`, `@SUM(`, `+`, `-`
- [x] **Étape 3 : data/mail_header.go** — injection Bcc/Cc/From/To, multipart MIME
- [x] **Étape 4 : data/jwt_attack.go** — alg:none, traversée de chemin kid, signature vide (décodage structurel)
- [x] **Étape 5 : data/prototype_pollution.go** — `__proto__`, `constructor`, `__defineGetter__/Setter__`
- [x] **Étape 6 : Compiler et valider**

---

### Tâche 11 : Détecteurs de fichiers et de données sensibles

**Fichiers :**
- Créer : `file/path_traversal.go`
- Créer : `file/upload.go`
- Créer : `file/data_leak.go`

- [x] **Étape 1 : file/path_traversal.go** — `../`, `..\\`, php://filter, octet nul, contournement par encodage URL
- [x] **Étape 2 : file/upload.go** — liste blanche d'extensions + analyse de contenu des balises PHP
- [x] **Étape 3 : file/data_leak.go** — carte bancaire, clé AWS, clé privée, chaîne de connexion DB, jeton API, JWT secret
- [x] **Étape 4 : Compiler et valider**

---

### Tâche 12 : Intégration Engine — RegisterAll

**Fichiers :**
- Modifier : `security.go`

- [x] **Étape 1 : Ajouter RegisterAll()** — enregistre les 32 détecteurs intégrés
- [x] **Étape 2 : Compiler** — `go build ./...`
- [x] **Étape 3 : Valider** — `feat: add RegisterAll for built-in detectors`

---

### Tâche 13 : Tests

**Fichiers :**
- Créer : `security_test.go`
- Créer : `injection/xss_test.go`, `sql_test.go`, `jndi_test.go`, `ssti_test.go`
- Créer : `protocol/ssrf_test.go`
- Créer : `file/path_traversal_test.go`, `data_leak_test.go`
- Créer : `data/jwt_attack_test.go`
- Créer : `storage/memory_test.go`

- [x] **Étape 1 : Écrire les tests** — chacun avec des cas de test positifs et négatifs
- [x] **Étape 2 : Exécuter** — `go test ./... -v`
- [x] **Étape 3 : Valider** — `test: add core engine and detector tests`

---

### Tâche 14 : Revue de code post-implémentation et corrections (2026-07-29)

- [x] **Revue de code complète** — 42 fichiers sources Go, 8 paquets
- [x] **Correction de bug #1** — `storage/file.go` : les erreurs de sérialisation JSON étaient ignorées silencieusement → vérification de l'erreur et retour
- [x] **Correction de bug #2** — `httpval/content_type.go` : une AllowList vide autorisait tous les Content-Type → valeur par défaut deny-all
- [x] **Correction de bug #3** — `protocol/xxe.go` : `&[a-z]+;` correspondait à tort aux entités HTML légitimes → restriction à une liste connue de protocoles malveillants
- [x] **Ajout des tests httpval** — 32 cas de test couvrant les 5 détecteurs (BodySize, ContentType, CSRFOrigin, IPBlacklist, Method)
- [x] **Tests complets** — `go test -count=1 ./...` 7/7 paquets réussis, `go vet` zéro avertissement

---

## Écarts entre le plan et la réalité

| Plan | Réalité | Raison |
|------|------|------|
| RegisterAll dans `security.go` | Paquet séparé `all/all.go` | Éviter les références circulaires, httpval dépend de storage mais pas les autres détecteurs |
| Redis dans le go.mod racine | Sous-module `storage/redis/` | Isoler la dépendance optionnelle |
| Receiver pointeur uniforme | Le paquet protocol utilisait des receivers par valeur | ✅ Tous convertis en receivers pointeur lors de la revue v2 |
| Tâches 4-12 Compiler et valider | Pas de validation incrémentale | Tout le code a été implémenté en une fois |

## Résumé de la couverture de tests

| Paquet | Fichiers de test | Nombre de tests |
|----|---------|--------|
| security | security_test.go | 5 |
| data | deserialization_test.go, csv_injection_test.go, mail_header_test.go, jwt_attack_test.go, prototype_pollution_test.go | 8 |
| file | path_traversal_test.go, data_leak_test.go, upload_test.go | 5 |
| httpval | httpval_test.go | 32 |
| injection | xss_test.go, sql_test.go, command_test.go, nosql_test.go, ldap_test.go, xpath_test.go, jndi_test.go, ssi_test.go, graphql_test.go, ssti_test.go | 10 |
| protocol | ssrf_test.go, xxe_test.go, header_injection_test.go, host_header_test.go, request_smuggling_test.go, open_redirect_test.go, cors_test.go, websocket_test.go, dns_rebinding_test.go | 9 |
| storage | memory_test.go | 4 |
| all | (aucun) | 0 |

> Le rapport complet est disponible dans `docs/superpowers/reports/2026-07-29-code-review-report-v2.md` — voir aussi [../reports/2026-07-29-code-review-report-v2.md](../reports/2026-07-29-code-review-report-v2.md)

---

Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
