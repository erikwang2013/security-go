# Attack Detection Package — Spécification de conception

## Vue d'ensemble

Bibliothèque de détection d'attaques en Go pur, avec interface unifiée + modèle de registre, couvrant 5 grandes catégories et 32 détecteurs. **Implémentation terminée (2026-07-29).**

## Structure du paquet

```
security-go/
├── go.mod
├── security.go              # Result, Severity, Detector interface, Engine
├── all/all.go               # RegisterAll — enregistre tous les détecteurs intégrés
├── injection/               # Attaques par injection (10)
├── protocol/                # Attaques protocole et requête (9)
├── httpval/                 # Validation de la couche HTTP (5)
├── data/                    # Attaques sur données et sérialisation (5)
├── file/                    # Fichiers et données sensibles (3)
└── storage/                 # Backends de stockage enfichables
    ├── storage.go           # Backend interface
    ├── memory.go            # Implémentation en mémoire (avec nettoyage TTL)
    ├── file.go              # Persistance dans un fichier JSON
    └── redis/               # Sous-module Redis (dépendance optionnelle)
```

## API principale

Toutes les interfaces API (`Result`, `Detector`, `Engine`, backend de stockage `Backend`, validateurs HTTP) sont documentées dans un document dédié : **[Documentation de l'API](../api.md)**

- Tous les détecteurs utilisent des motifs regex précompilés

## Détecteurs

| Catégorie | Nom | Motifs clés |
|----------|------|-------------|
| injection | xss | `<script>`, `on[a-z]+=`, `javascript:`, vecteurs SVG/CSS |
| injection | sql | UNION SELECT, `/**/`, sleep/benchmark, aveugle booléen, énumération de schéma |
| injection | command | accent grave, `$()`, tube, `/dev/tcp`, fonctions d'exécution PHP |
| injection | nosql | MongoDB `$ne`/`$gt`/`$regex`/`$where`, contournement d'authentification |
| injection | ldap | opérateurs de filtre `(`, `)`, `&`, `\|`, `*` |
| injection | xpath | contournement booléen `1=1`, `' or '1'='1` |
| injection | jndi | `${jndi:ldap://`, `${lower:j}`, `${env:}` |
| injection | ssi | `<!--#exec`, `<!--#include`, `<!--#echo` |
| injection | graphql | `__schema`, `__type`, requête imbriquée profonde, détection mutation |
| injection | ssti | Jinja2 `{{}}`, FreeMarker `${}`, ERB `<% %>`, MRO Python |
| protocol | ssrf | IP interne, 169.254.169.254, loopback IPv6, gopher/dict |
| protocol | xxe | `<!ENTITY`, entités paramétrées, DOCTYPE |
| protocol | header_injection | CRLF `%0d%0a`, injection Set-Cookie/Location |
| protocol | host_header | Injection CRLF dans Host, empoisonnement X-Forwarded-Host |
| protocol | request_smuggling | Incohérence TE/CL, double TE, en-tête replié |
| protocol | open_redirect | `//evil.com`, `javascript:`, `data:` |
| protocol | cors | Origin: null, injection d'en-têtes ACA* |
| protocol | websocket | Injection Upgrade, Origin null, ws:// |
| protocol | dns_rebinding | IP interne dans l'en-tête Host, localhost, nom d'hôte sans TLD |
| httpval | method | Liste blanche GET/POST/PUT/DELETE/HEAD/OPTIONS/PATCH → 405 |
| httpval | body_size | Vérification de taille maximale → 413 (10 Mo par défaut) |
| httpval | content_type | Liste blanche MIME → 415 |
| httpval | csrf_origin | Correspondance Origin cross-origin vs Host |
| httpval | ip_blacklist | Limitation de débit par fenêtre → bannissement automatique (5/60 s → 15 min) |
| data | deserialization | PHP `O:nombre:`, `C:nombre:`, unserialize() |
| data | csv_injection | Préfixes de formule `=`, `@`, `+`, `-` |
| data | mail_header | Injection Bcc/Cc/From/To, MIME |
| data | jwt_attack | alg:none, traversée de chemin kid, signature vide |
| data | prototype_pollution | `__proto__`, `constructor`, `__defineGetter__` |
| file | path_traversal | `../`, `..\\`, php://filter, octet nul |
| file | upload | Liste blanche d'extensions + analyse de contenu des balises PHP |
| file | data_leak | Carte bancaire, clé AWS, clé privée, chaîne de connexion, JWT secret |

## Hors du périmètre

- Pas de middleware HTTP (bibliothèque de détection pure)
- Pas d'interception de requêtes en temps réel (l'appelant invoque la détection)
- Pas de blocage d'attaques (détection uniquement ; ip_blacklist fournit le support de liste noire)

## État de l'implémentation (2026-07-29)

- **Les 32 détecteurs sont implémentés** — point d'enregistrement `all.RegisterAll(engine)`
- **Couverture de tests** — 7/8 paquets ont des tests (le paquet `all` reste à faire), 32 tests ajoutés pour httpval
- **Revue de code terminée** — 3 bugs corrigés (voir le rapport de revue), `go vet` zéro avertissement
- **Limites connues** — le sous-module `storage/redis/` nécessite `go mod tidy` ; le style de receiver du paquet protocol reste à uniformiser
- **Rapport** — `docs/superpowers/reports/2026-07-29-code-review-report.md`

---

Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
