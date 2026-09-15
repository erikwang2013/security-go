# Security Go — bibliothèque de détection d'attaques

[简体中文](../../../README.md) · [English](../../../README-EN.md) · [Documentation de l'API](api.md)

Paquet de détection d'attaques écrit en Go, couvrant **36 détecteurs**, **6 grandes catégories d'attaques** et **3 backends de stockage enfichables**. Interface unifiée + modèle de registre, bibliothèque de détection pure, compatible avec tout framework HTTP Go.

## Conception

### Principes fondamentaux

- **Détection zéro dépendance** — tous les détecteurs utilisent uniquement `regexp` de la bibliothèque standard Go, aucune dépendance externe
- **Interface unifiée** — chaque détecteur implémente l'interface `Detector` (`Name()` + `Detect()`), gérée de manière centralisée par le registre `Engine`
- **Expressions régulières précompilées** — tous les motifs sont compilés à l'initialisation des `var`, zéro surcoût à l'exécution
- **Configuration à la demande** — les détecteurs d'injection/protocole/données/fichier sont prêts à l'emploi ; les validateurs HTTP et la détection de sécurité de session nécessitent une configuration personnalisée

### Architecture

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
   │   (10)      │   │   (9)       │   │       (5)           │   │    (3)        │
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
   │     (7)         │                                         │  ┌──────────────┐   │
   │                 │                                         │  │   Backend    │   │
   │  method, size,  │                                         │  │   interface  │   │
   │  type, csrf,    │                                         │  └──┬───┬───┬───┘   │
   │  cookie,nested  │                                         │                    │
   │  ip_blacklist   │◄────── utilise storage.Backend ────────►│  Memory File Redis │
   │  (paramètres    │                                         │                    │
   │  requis)        │                                         └────────────────────┘
   └─────────────────┘

   ┌─────────────────────────────────────────────────────────────────────┐
   │  session (2)   outside the Engine registry                          │
   │                                                                     │
   │  Tracker (session_guard)  +  Signer (data_tamper)                   │
   │  Issue / Check / Observe / Guard / Revoke    Sign / Verify          │
   └─────────────────────────────────────────────────────────────────────┘
```

> Le paquet `session` ne passe pas par l'enregistrement `Engine` : la validation de session doit lire le `*http.Request` complet (token, IP client, User-Agent),
> et nécessite que l'application fournisse le stockage et la clé, il est donc appelé directement comme middleware — voir « Configuration de la sécurité de session » ci-dessous.

### Flux de données

```
HTTP Request
     │
     ▼
┌──────────────┐     ┌─────────────────┐     ┌──────────────┐
│ collectInputs│────▶│  DetectAll()    │────▶│  []*Result   │
│ URL, Query,  │     │  appel de chaque│     │  résultats   │
│ Headers,     │     │  détecteur      │     │  agrégés     │
│ Cookies      │     │  Detect(input)  │     │              │
└──────────────┘     └─────────────────┘     └──────────────┘
```

### Niveaux de gravité

| Niveau | Description | Exemples typiques |
|------|------|---------|
| `SeverityLow` | Risque faible | Méthode HTTP non autorisée, Content-Type incompatible |
| `SeverityMedium` | Risque moyen | Problème de configuration CORS, redirection ouverte, introspection GraphQL |
| `SeverityHigh` | Risque élevé | XSS, injection SQL, SSRF, traversée de chemin |
| `SeverityCritical` | Critique | Injection de commande, JNDI, SSTI, XXE, fuite de données |

## Fonctionnalités

### Attaques par injection (10)

| Détecteur | Motifs détectés |
|--------|---------|
| **XSS** | `<script>`, gestionnaires d'événements `on[a-z]+=`, pseudo-protocole `javascript:`, injection SVG/CSS, `eval()`, `document.cookie` |
| **Injection SQL** | `UNION SELECT` (avec contournement `/**/`), `sleep/benchmark/pg_sleep`, injection aveugle booléenne, énumération `information_schema`, `xp_cmdshell` |
| **Injection de commande** | Accents graves, `$()`, tube (`\|`), `/dev/tcp`, fonctions PHP `system/exec/shell_exec`, exécution en chaîne `&&` `;` `\|\|` |
| **Injection NoSQL** | Opérateurs MongoDB `$ne` `$gt` `$regex` `$where`, `$func`, injection de clés JSON |
| **Injection LDAP** | Opérateurs de filtre `(\|(&(!`, `objectClass=*`, contournement par encodage URL |
| **Injection XPATH** | Contournement booléen `' or '1'='1`, `string-length()`, `count()` |
| **JNDI/Log4Shell** | `${jndi:ldap://`, obfuscation `${lower:j}`, variables d'environnement `${env:}`, protocoles `ldap/rmi/dns` |
| **Injection SSI** | `<!--#exec cmd=`, `<!--#include file=`, `<!--#echo var=` |
| **Injection GraphQL** | Introspection `__schema`/`__type`, DoS par imbrication profonde (5 niveaux+), détection `mutation` |
| **SSTI** | Jinja2 `{{}}`, FreeMarker `${}`, ERB `<% %>`, traversée du MRO Python, accès `config/self` |

### Attaques protocole et requête (9)

| Détecteur | Motifs détectés |
|--------|---------|
| **SSRF** | IP internes (127/10/172.16/192.168), `169.254.169.254`, loopback IPv6, protocoles `gopher/dict/file/ftp` |
| **XXE** | `<!ENTITY SYSTEM/PUBLIC`, entités paramétrées `%entity;`, déclaration DOCTYPE |
| **Injection d'en-tête HTTP** | CRLF `%0d%0a` / `\r\n`, injection Set-Cookie/Location/Content-Length |
| **Attaque d'en-tête Host** | Injection CRLF dans Host, empoisonnement `X-Forwarded-Host`, `X-Original-URL` |
| **Contrebande de requêtes** | Incohérence Transfer-Encoding/Content-Length, double en-tête TE, en-tête replié `\x0b` |
| **Redirection ouverte** | URL relative au protocole `//evil.com`, pseudo-protocoles `javascript:/data:` |
| **Contournement CORS** | `Origin: null`, injection d'en-têtes `Access-Control-Allow-*` |
| **Détournement WebSocket** | Injection d'en-tête Upgrade, contournement Origin null, URL `ws://` |
| **Rebinding DNS** | IP internes dans l'en-tête Host, localhost, noms d'hôte courts sans TLD |

### Validation de la couche HTTP (7)
| **Profondeur d'imbrication JSON** | Analyse en flux avec `json.Decoder` : signale une bombe JSON dès que la profondeur d'imbrication ou le nombre d'éléments dépasse la limite (profondeur par défaut 32). Un JSON invalide ou tronqué ne déclenche jamais |
| **Attributs Set-Cookie** | Signale un `Set-Cookie` sans `Secure`/`HttpOnly`/`SameSite`, à valeur trop longue ou vide ; les attributs manquants sont regroupés en un seul résultat |

| Détecteur | Description |
|--------|------|
| **Méthode HTTP** | Autorise uniquement GET/POST/PUT/DELETE/HEAD/OPTIONS/PATCH, les autres déclenchent une alerte |
| **Taille du corps** | Alerte si dépassement de la limite (10 Mo par défaut) |
| **Content-Type** | Autorise uniquement la liste blanche de types MIME configurée |
| **Origin CSRF** | Vérifie que l'Origin des requêtes cross-origin correspond au Host, liste blanche supplémentaire prise en charge |
| **Liste noire IP** | Bannissement automatique après N attaques dans la fenêtre (par défaut 5/60 s → bannissement 15 min), stockage File/Redis/Memory pris en charge |

### Attaques sur données et sérialisation (5)

| Détecteur | Motifs détectés |
|--------|---------|
| **Désérialisation** | Objets sérialisés `O:nombre:` / `C:nombre:`, `unserialize()`, méthodes magiques (`__wakeup`/`__destruct`) ; couvre les charges PHP / pickle / Java / .NET |
| **Injection CSV** | `=cmd\|`, `@SUM(`, préfixes de formule `+`/`-`, `HYPERLINK`/`DDE` |
| **Injection d'en-tête d'e-mail** | Injection Bcc/Cc/From/To, multipart MIME, paramètre boundary |
| **Attaque JWT** | Contournement `alg: none`, traversée de chemin `kid`, détection de signature vide (analyse par décodage structurel) |
| **Pollution de prototype** | Clés `__proto__`/`constructor`, `__defineGetter__`/`__defineSetter__` |

### Fichiers et données sensibles (3)

| Détecteur | Motifs détectés |
|--------|---------|
| **Traversée de chemin** | `../`, `..\\`, `php://filter`/`php://input`, octet nul, contournement par encodage URL, `/etc/passwd` |
| **Téléversement malveillant** | Liste blanche d'extensions (15) + analyse de contenu des balises PHP `<?php`/`<?=` |
| **Fuite de données** | Numéros de carte bancaire, AWS Access Key, clés privées `-----BEGIN`, chaînes de connexion de base de données, jetons API, JWT Secret, PAT GitHub |

### Sécurité de session (2)

| Détecteur | Motifs détectés |
|--------|---------|
| **Garde de session** (`session_guard`) | Liaison du token au client au moment de l'établissement de la session, comparée à chaque requête : un changement de User-Agent ou d'empreinte d'appareil détermine un **détournement du client** (Critical) ; une IP client tombant dans un autre sous-réseau ou pays détermine une **connexion distante** (High/Critical) ; `Observe()` compare les sous-réseaux historiques lors de la connexion et alerte dès qu'un nouveau sous-réseau apparaît. La session est renouvelée par glissement, `Revoke()` permet une invalidation immédiate ; `RecordFailure()` compte les tentatives échouées et verrouille le jeton dès que le seuil est atteint dans la fenêtre, `Check()` renvoie alors `token_locked`, et `ClearFailures()` remet le compteur à zéro après une connexion réussie |
| **Falsification de données** (`data_tamper`) | Signature HMAC-SHA256 des paramètres de requête (`horodatage.nonce.signature`), identifiant la modification de paramètres, une clé non correspondante, un horodatage hors tolérance et la relecture de signature (compteur de nonce) |

### Backends de stockage (3)

| Backend | Description |
|------|------|
| **Memory** | `sync.Mutex` + map, nettoyage automatique des entrées expirées toutes les 30 s |
| **File** | Persistance dans un fichier JSON, flush à la fermeture |
| **Redis** | Sous-module indépendant, Pipeline Incr + TTL, nécessite `go-redis/v9` |

## Utilisation

### Installation

```bash
go get github.com/erikwang2013/security-go
```

### Démarrage rapide

```go
package main

import (
    "fmt"
    "github.com/erikwang2013/security-go"
    "github.com/erikwang2013/security-go/all"
)

func main() {
    e := security.NewEngine()
    all.RegisterAll(e) // enregistre en une fois les 27 détecteurs sans configuration

    // Détection individuelle
    r := e.Detect("xss", "<script>alert(1)</script>")
    fmt.Printf("Détecté: %v, gravité: %d\n", r.Detected, r.Severity)

    // Détection complète
    for _, r := range e.DetectAll("' OR '1'='1") {
        fmt.Printf("[%s] %s\n", r.Name, r.Message)
    }
}
```

### Détection de requêtes HTTP

```go
func handler(w http.ResponseWriter, r *http.Request) {
    e := security.NewEngine()
    all.RegisterAll(e)

    for _, result := range e.DetectRequest(r) {
        if result.Detected {
            log.Printf("Attaque détectée: [%s] %s", result.Name, result.Message)
        }
    }
}
```

### Configuration des validateurs HTTP

```go
// Validation de la méthode
e.Register(&httpval.Method{})

// Limite de taille du corps
e.Register(httpval.NewBodySize(5 * 1024 * 1024)) // 5 Mo

// Liste blanche Content-Type
e.Register(httpval.NewContentType([]string{
    "application/json", "application/x-www-form-urlencoded",
}))

// Vérification de l'Origin CSRF
e.Register(&httpval.CSRFOrigin{
    Host: "example.com", AllowList: []string{"api.example.com"},
})

// Liste noire IP (bannissement automatique : 5/60 s → bannissement 15 min)
mem := storage.NewMemory()
defer mem.Close()
bl := httpval.NewIPBlacklist(mem)
e.Register(bl)

// Enregistrement lors d'une attaque
blocked, _ := bl.RecordAttack(clientIP)
```

### Configuration de la sécurité de session

Le paquet `session` s'utilise directement comme middleware, sans passer par `Engine`. Le stockage doit être fourni par l'application (une implémentation en mémoire est fournie par défaut, remplaçable par Redis, etc.) :

```go
import "github.com/erikwang2013/security-go/session"

st := session.NewMemoryStore()
defer st.Close()

tr := session.NewTracker(st)
tr.CountryOf = geo.Lookup // 可选：接入 GeoIP，用于识别跨国家登录

// 登录成功后绑定会话（token 由你的登录流程生成）
// 异地登录检测：比对该用户历史登录网段，出现新网段即告警
if res := tr.Observe("user-1", r); res.Detected {
    log.Printf("[%s] %s (%v)", res.Name, res.Message, res.Details["reason"])
}
if err := tr.Issue(token, r); err != nil {      // 绑定 token → IP 网段 / UA / 设备指纹
    http.Error(w, "session error", http.StatusInternalServerError)
    return
}

// 保护路由：命中劫持或异地登录直接返回 401
mux.Handle("/api/", tr.Guard(apiHandler))

// 或只做检测、自行决定处置
if res := tr.Check(r); res.Detected {
    log.Printf("[%s] %s (%v)", res.Name, res.Message, res.Details["reason"])
}

// 登出
tr.Revoke(token)
```

Détection de falsification de données : le client et le serveur partagent une clé, le client signe les paramètres et le serveur recalcule la vérification :

```go
signer := session.NewSigner(secret, storage.NewMemory()) // 第二个参数用于拦截签名重放，可为 nil

sig, _ := signer.Sign(map[string]string{"amount": "100", "to": "bob"}) // 客户端：随参数一起提交

if res := signer.Verify(map[string]string{"amount": "100", "to": "bob"}, sig); res.Detected {
    log.Printf("[%s] %s (%v)", res.Name, res.Message, res.Details["reason"])
}
```

> `TrustProxyHeaders` est désactivé par défaut : `X-Forwarded-For` / `X-Real-IP` sont contrôlables par le client, ne l'activez qu'en amont d'un reverse proxy dédié.
> `FailClosed` est désactivé par défaut (passage en cas de panne de stockage, comme pour `IPBlacklist`) ; son activation est recommandée pour les activités sensibles aux sessions.

### Détecteur personnalisé

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

### Documents associés

- [Documentation de l'API](api.md) — types principaux, interfaces Detector/Engine, interface des backends de stockage, validateurs HTTP
- [Spécification de conception](specs/2026-07-29-attack-detection-design.md) — structure du paquet, catalogue des détecteurs
- [Plan de mise en œuvre](plans/2026-07-29-attack-detection-plan.md) — plan de tâches pas à pas et comparaison des écarts de mise en œuvre
- [Rapport de revue de code](reports/2026-07-29-code-review-report.md) — corrections de bugs, couverture de tests, évaluation de l'architecture

---

## Documentation multilingue

| Langue | Documentation |
|------|------|
| 简体中文 | [README.md](../../../README.md) |
| English | [README-EN.md](../../../README-EN.md) · [docs/i18n/en/README.md](../en/README.md) |
| 한국어 | [docs/i18n/ko/README.md](../ko/README.md) |
| Русский | [docs/i18n/ru/README.md](../ru/README.md) |
| Deutsch | [docs/i18n/de/README.md](../de/README.md) |
| Français | [README.md](README.md) |
| Español | [docs/i18n/es/README.md](../es/README.md) |
| Português | [docs/i18n/pt/README.md](../pt/README.md) |
| हिन्दी | [docs/i18n/hi/README.md](../hi/README.md) |
| العربية | [docs/i18n/ar/README.md](../ar/README.md) |
| বাংলা | [docs/i18n/bn/README.md](../bn/README.md) |
| Bahasa Indonesia | [docs/i18n/id/README.md](../id/README.md) |
| 日本語 | [docs/i18n/ja/README.md](../ja/README.md) |

Index : [docs/i18n/README.md](../README.md)

---

## Soutien par don

Si ce projet vous est utile, n'hésitez pas à soutenir son développement :

| Moyen | QR code |
|------|--------|
| Alipay | ![Alipay](images/alipay.png) |
| WeChat Pay | ![WeChat Pay](images/weixinpay.png) |

### Don par virement bancaire international

**Informations sur le bénéficiaire**

- Nom du bénéficiaire : WANG KEXUN
- Numéro de compte du bénéficiaire : 881015918251

**Banque du bénéficiaire (ZA Bank)**

- Code SWIFT : `AABLHKHHXXX`
- Nom de la banque : ZA Bank Limited
- Code bancaire : 387
- Adresse de la banque : Core F, Cyberport 3, 100 Cyberport Road, Hong Kong

**Banque correspondante pour les virements transfrontaliers (si nécessaire)**

> À noter : il s'agit des informations de la banque correspondante (banque intermédiaire) pour les virements transfrontaliers, et non de la banque du bénéficiaire. Veuillez vérifier auprès de votre banque émettrice si les informations de la banque correspondante sont requises.

- Pour les virements en dollars de Hong Kong, en RMB et en dollars américains, la banque correspondante est Citibank :
  - Nom de la banque : Citibank N.A. Hong Kong
  - Code SWIFT : `CITIHKHXXXX`
  - Code bancaire : 006
  - Nom de la succursale : Hong Kong Branch
  - Numéro de succursale : 391
  - Adresse de la banque : Citibank Tower, Citibank Plaza, 3 Garden Road, Central, Hong Kong
- Pour les virements dans d'autres devises, la banque correspondante est BNY Mellon :
  - Nom de la banque : THE BANK OF NEW YORK MELLON
  - Code SWIFT : `IRVTUS3NXXX`
  - Adresse de la banque : THE BANK OF NEW YORK MELLON, 240 GREENWICH STREET, NEW YORK, United States

---

## English

See [README-EN.md](../../../README-EN.md) for the full English documentation.

---

Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
