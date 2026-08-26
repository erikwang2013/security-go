# Relatório de revisão de código do Security-Go

**Data**: 2026-07-29  
**Projeto**: github.com/erikwang2013/security-go  
**Escopo da revisão**: 42 arquivos-fonte Go, 8 pacotes (security, all, data, file, httpval, injection, protocol, storage)

---

## 1. Resultados dos testes

```
ok      github.com/erikwang2013/security-go       0.004s
?       github.com/erikwang2013/security-go/all   [no test files]
ok      github.com/erikwang2013/security-go/data  0.005s
ok      github.com/erikwang2013/security-go/file  0.006s
ok      github.com/erikwang2013/security-go/httpval 0.004s  (32 testes complementares)
ok      github.com/erikwang2013/security-go/injection 0.005s
ok      github.com/erikwang2013/security-go/protocol  0.005s
ok      github.com/erikwang2013/security-go/storage   0.159s
```

- `go vet ./...` aprovado, sem avisos
- Todos os testes aprovados
- **Pacote sem testes**: `all` (único restante)

---

## 2. Bugs corrigidos

### Bug #1 [Crítico] `storage/file.go:101` — erros de serialização JSON ignorados silenciosamente

**Problema**: no método `Close()`, `data, _ := json.Marshal(out)` ignorava o erro de serialização. Se a serialização JSON falhasse, `data` seria nil e `os.WriteFile` escreveria dados vazios, **causando a perda total dos dados persistidos**.

**Correção**: verificar o valor de erro retornado por `json.Marshal` e retornar o erro imediatamente em caso de falha.

```go
// Antes da correção
data, _ := json.Marshal(out)
return os.WriteFile(f.path, data, 0644)

// Após a correção
data, err := json.Marshal(out)
if err != nil {
    return err
}
return os.WriteFile(f.path, data, 0644)
```

### Bug #2 [Crítico] `httpval/content_type.go:34` — AllowList vazia liberava todos os Content-Type

**Problema**: a condição `if len(c.Allowed) == 0 || c.Allowed[mt]` significava que, quando a AllowList estava vazia, **todos os Content-Type eram liberados**. O padrão de segurança deveria ser deny-all.

**Correção**: remover a condição `len(c.Allowed) == 0`; uma AllowList vazia passa a cair no ramo de rejeição.

```go
// Antes da correção
if len(c.Allowed) == 0 || c.Allowed[mt] {
    return &security.Result{Name: c.Name(), Detected: false}
}

// Após a correção
if c.Allowed[mt] {
    return &security.Result{Name: c.Name(), Detected: false}
}
```

### Bug #3 [Médio] `protocol/xxe.go:15` — `&[a-z]+;` gerava falso positivo em todas as entidades HTML/XML legítimas

**Problema**: a regex `(?i)&[a-z]+;` corresponde a todas as referências de entidade padrão (`&amp;`, `&lt;`, `&gt;`, etc.), fazendo com que qualquer requisição contendo HTML/XML legítimo fosse erroneamente sinalizada como ataque XXE.

**Correção**: restringir o escopo de correspondência aos prefixos de protocolos maliciosos conhecidos.

```go
// Antes da correção
regexp.MustCompile(`(?i)&[a-z]+;`),

// Após a correção
regexp.MustCompile(`(?i)&(?:xxe|file|http|ftp|gopher|dict|data|expect);`),
```

---

## 3. Problemas secundários encontrados (não corrigidos, requerem avaliação)

### Problema #1: pacote `all` sem cobertura de testes

A função `RegisterAll()` em `all/all.go` não tem nenhum teste. Deve-se adicionar testes para verificar que todos os detectors registrados podem ser invocados normalmente.

### Problema #2: testes do pacote `httpval` complementados ✅ (resolvido)

Foi adicionado `httpval/httpval_test.go` (32 casos de teste), cobrindo `BodySize` (7 testes), `ContentType` (7 testes), `CSRFOrigin` (8 testes), `IPBlacklist` (6 testes) e `Method` (3 testes). Inclui valores de contorno, entradas inválidas e verificação de deny-all com AllowList vazia.

### Problema #3: regex de número de cartão de crédito em `data/data_leak.go` muito ampla

`\b(?:\d[ -]*?){13,16}\b` corresponde a qualquer sequência de 13 a 16 dígitos.

### Problema #4: submódulo `storage/redis/` incompleto

- `go.mod` não declara a dependência do módulo pai
- Falta o arquivo `go.sum`

### Problema #5: estilos de receiver inconsistentes entre os pacotes protocol e injection

- O pacote `injection` usa pointer receivers: `func (d *XSS) Name() string`
- O pacote `protocol` usa value receivers: `func (d CORS) Name() string`

### Problema #6: `injection/xss.go` — `&#x?[0-9a-f]+;?` corresponde a referências numéricas de caracteres HTML legítimas

---

## 4. Avaliação geral da arquitetura

| Dimensão | Nota | Observações |
|------|------|------|
| Design da interface | ★★★★☆ | Interface `Detector` + padrão de orquestração `Engine` claros |
| Consistência do código | ★★★☆☆ | Estilo de receiver não uniforme |
| Tratamento de erros | ★★★☆☆ | Antes da correção havia erros silenciosamente engolidos; melhorou após a correção |
| Cobertura de testes | ★★★★☆ | `httpval` recebeu testes complementares; pacote `all` ainda carece |
| Padrões de segurança | ★★★☆☆ | Problema da AllowList vazia do ContentType corrigido |
| Precisão da detecção | ★★★☆☆ | Algumas regex apresentam risco de falso positivo (xxe parcialmente corrigido) |

---

## 5. Prioridades sugeridas

| Prioridade | Item |
|--------|------|
| ~~P0~~ | ~~Complementar testes do pacote `httpval`~~ ✅ Concluído (32 testes, 5 detectors) |
| P1 | Complementar testes do pacote `all` |
| P1 | Corrigir o go.mod do submódulo `storage/redis/` |
| P2 | Uniformizar o estilo de receiver para pointer receivers |
| P2 | Avaliar a taxa de falsos positivos das regex de cartão de crédito/XSS |

---

Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
