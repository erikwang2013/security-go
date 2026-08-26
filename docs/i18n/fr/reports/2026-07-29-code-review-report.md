# Rapport de revue de code Security-Go

**Date** : 2026-07-29  
**Projet** : github.com/erikwang2013/security-go  
**Périmètre de la revue** : 42 fichiers sources Go, 8 paquets (security, all, data, file, httpval, injection, protocol, storage)

---

## I. Résultats des tests

```
ok      github.com/erikwang2013/security-go       0.004s
?       github.com/erikwang2013/security-go/all   [no test files]
ok      github.com/erikwang2013/security-go/data  0.005s
ok      github.com/erikwang2013/security-go/file  0.006s
ok      github.com/erikwang2013/security-go/httpval 0.004s  (32 tests ajoutés)
ok      github.com/erikwang2013/security-go/injection 0.005s
ok      github.com/erikwang2013/security-go/protocol  0.005s
ok      github.com/erikwang2013/security-go/storage   0.159s
```

- `go vet ./...` réussi, aucun avertissement
- Tous les tests réussissent
- **Paquet sans tests** : `all` (seul restant)

---

## II. Bugs corrigés

### Bug #1 [Critique] `storage/file.go:101` — Erreurs de sérialisation JSON ignorées silencieusement

**Problème** : Dans la méthode `Close()`, `data, _ := json.Marshal(out)` ignore l'erreur de sérialisation. Si la sérialisation JSON échoue, `data` est nil et `os.WriteFile` écrit des données vides, **ce qui entraîne la perte totale des données persistées**.

**Correctif** : Vérifier la valeur de retour d'erreur de `json.Marshal` et renvoyer immédiatement l'erreur en cas d'échec.

```go
// Avant correction
data, _ := json.Marshal(out)
return os.WriteFile(f.path, data, 0644)

// Après correction
data, err := json.Marshal(out)
if err != nil {
    return err
}
return os.WriteFile(f.path, data, 0644)
```

### Bug #2 [Critique] `httpval/content_type.go:34` — Une AllowList vide autorise tous les Content-Type

**Problème** : La condition `if len(c.Allowed) == 0 || c.Allowed[mt]` signifie que lorsque l'AllowList est vide, **tous les Content-Type sont autorisés**. La valeur par défaut sécurisée devrait être deny-all.

**Correctif** : Retirer la condition `len(c.Allowed) == 0`, une AllowList vide tombe dans la branche de refus.

```go
// Avant correction
if len(c.Allowed) == 0 || c.Allowed[mt] {
    return &security.Result{Name: c.Name(), Detected: false}
}

// Après correction
if c.Allowed[mt] {
    return &security.Result{Name: c.Name(), Detected: false}
}
```

### Bug #3 [Moyen] `protocol/xxe.go:15` — `&[a-z]+;` correspond à tort à toutes les entités HTML/XML légitimes

**Problème** : L'expression régulière `(?i)&[a-z]+;` correspond à toutes les références d'entités standard (`&amp;`, `&lt;`, `&gt;`, etc.), ce qui fait que toute requête contenant du HTML/XML légitime est signalée à tort comme une attaque XXE.

**Correctif** : Restreindre la correspondance aux préfixes de protocoles malveillants connus.

```go
// Avant correction
regexp.MustCompile(`(?i)&[a-z]+;`),

// Après correction
regexp.MustCompile(`(?i)&(?:xxe|file|http|ftp|gopher|dict|data|expect);`),
```

---

## III. Problèmes mineurs identifiés (non corrigés, à évaluer)

### Problème #1 : Aucune couverture de test pour le paquet `all`

La fonction `RegisterAll()` de `all/all.go` n'a aucun test. Des tests devraient être ajoutés pour vérifier que tous les détecteurs enregistrés peuvent être appelés normalement.

### Problème #2 : Tests du paquet `httpval` ajoutés ✅ (résolu)

`httpval/httpval_test.go` a été ajouté (32 cas de test), couvrant `BodySize` (7 tests), `ContentType` (7 tests), `CSRFOrigin` (8 tests), `IPBlacklist` (6 tests), `Method` (3 tests). Comprend les valeurs limites, les entrées erronées et la vérification deny-all de l'AllowList vide.

### Problème #3 : L'expression régulière des numéros de carte bancaire dans `data/data_leak.go` est trop large

`\b(?:\d[ -]*?){13,16}\b` correspond à n'importe quelle séquence de 13 à 16 chiffres.

### Problème #4 : Le sous-module `storage/redis/` est incomplet

- `go.mod` ne déclare pas la dépendance au module parent
- Le fichier `go.sum` est manquant

### Problème #5 : Style de receiver incohérent entre les paquets protocol et injection

- Le paquet `injection` utilise des receivers pointeur : `func (d *XSS) Name() string`
- Le paquet `protocol` utilise des receivers par valeur : `func (d CORS) Name() string`

### Problème #6 : `injection/xss.go` — `&#x?[0-9a-f]+;?` correspond aux références numériques de caractères HTML légitimes

---

## IV. Évaluation globale de l'architecture

| Dimension | Note | Description |
|------|------|------|
| Conception de l'interface | ★★★★☆ | L'interface `Detector` + le modèle d'orchestration `Engine` sont clairs |
| Cohérence du code | ★★★☆☆ | Style de receiver non uniforme |
| Gestion des erreurs | ★★★☆☆ | Des erreurs étaient avalées silencieusement avant correction ; amélioré depuis |
| Couverture de tests | ★★★★☆ | Tests ajoutés pour `httpval`, le paquet `all` manque encore |
| Valeurs par défaut sécurisées | ★★★☆☆ | Problème de l'AllowList vide de ContentType corrigé |
| Précision de détection | ★★★☆☆ | Certaines expressions régulières présentent un risque de faux positifs (xxe partiellement corrigé) |

---

## V. Priorités recommandées

| Priorité | Élément |
|--------|------|
| ~~P0~~ | ~~Ajouter les tests du paquet `httpval`~~ ✅ Terminé (32 tests, 5 détecteurs) |
| P1 | Ajouter les tests du paquet `all` |
| P1 | Corriger le go.mod du sous-module `storage/redis/` |
| P2 | Uniformiser le style de receiver en receiver pointeur |
| P2 | Évaluer le taux de faux positifs des expressions régulières carte bancaire/XSS |

---

Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
