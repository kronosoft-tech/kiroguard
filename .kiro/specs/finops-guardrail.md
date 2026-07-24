# Especificación: Módulo 4 — FinOps Guardrail

## Resumen

El módulo **FinOps Guardrail** es una herramienta MCP que analiza código fuente Go para detectar patrones costosos en la nube (AWS) y estima el impacto económico mensual antes del despliegue. Combina análisis estático de AST, fórmulas de estimación basadas en precios públicos de AWS, y explicaciones generadas por LLM (con fallback heurístico).

**Método MCP:** `finops/analyze`  
**Paquete:** `internal/finops/`  
**Archivos principales:**
- `detector.go` — Detección de patrones vía AST
- `estimator.go` — Fórmulas de estimación de costo
- `handler.go` — Orquestador y handler MCP

---

## 1. Reglas de Detección de Costos (`detector.go`)

El `PatternDetector` parsea el código fuente con `go/parser` y recorre el AST buscando 4 patrones costosos:

### 1.1. N+1 Query (`n_plus_1_query`)

| Campo | Valor |
|-------|-------|
| **Trigger** | Llamada a función de base de datos dentro de un `for` o `range` |
| **Funciones detectadas** | `Query`, `QueryRow`, `QueryContext`, `QueryRowContext`, `Exec`, `ExecContext`, `Find`, `FindOne`, `FindAll`, `Get`, `GetItem`, `GetItems`, `Select`, `SelectContext`, `Scan` |
| **Heurística adicional** | Cualquier función cuyo nombre (case-insensitive) contenga `"query"` o `"findby"` |
| **Nodo AST** | `*ast.ForStmt` o `*ast.RangeStmt` con `*ast.CallExpr` descendiente |

**Ejemplo detectado:**
```go
for _, id := range ids {
    db.QueryRow("SELECT * FROM users WHERE id = ?", id) // <- N+1
}
```

### 1.2. Unpaginated DynamoDB Scan (`unpaginated_scan`)

| Campo | Valor |
|-------|-------|
| **Trigger** | Llamada a `Scan` o `Query` con argumento struct de tipo DynamoDB que **no** contiene el campo `Limit` |
| **Tipos reconocidos** | `ScanInput`, `QueryInput`, `dynamodb.ScanInput`, `dynamodb.QueryInput`, `types.ScanInput`, `types.QueryInput` |
| **Validación** | Se verifica que el `*ast.CompositeLit` (directo o con `&`) NO tenga `KeyValueExpr` con key `"Limit"` |

**Ejemplo detectado:**
```go
client.Scan(&dynamodb.ScanInput{
    TableName: &tableName,
    // Sin Limit -> full table scan
})
```

**No se detecta si `Limit` está presente:**
```go
client.Scan(&dynamodb.ScanInput{
    TableName: &tableName,
    Limit:     &limit, // OK
})
```

### 1.3. Lambda sin MemorySize (`lambda_no_memory`)

| Campo | Valor |
|-------|-------|
| **Trigger** | `*ast.CompositeLit` de tipo Lambda create sin campo `MemorySize` |
| **Tipos reconocidos** | `CreateFunctionInput`, `lambda.CreateFunctionInput`, `types.CreateFunctionInput` |

### 1.4. Lambda sin Timeout (`lambda_no_timeout`)

| Campo | Valor |
|-------|-------|
| **Trigger** | `*ast.CompositeLit` de tipo Lambda create sin campo `Timeout` |
| **Tipos reconocidos** | (mismos que 1.3) |

**Nota:** Un solo `CreateFunctionInput` puede generar ambos hallazgos si le faltan los dos campos.

---

## 2. Fórmulas de Estimación de Costo (`estimator.go`)

### 2.1. Constantes Base (precios públicos AWS)

| Constante | Valor | Descripción |
|-----------|-------|-------------|
| `hoursPerMonth` | 730 | Promedio horas/mes (365×24/12) |
| `dynamoDBReadCostPerItem` | $0.000001 | Costo por lectura de item DynamoDB |
| `unpaginatedScanCostPerItem` | $0.0000025 | Costo por item en scan completo |
| `lambdaMBSecondCost` | $0.0000000163 | Costo por MB-segundo Lambda |
| `lambdaGBSecondCost` | $0.0000166667 | Costo por GB-segundo Lambda |

### 2.2. Parámetro de Entrada: `requestsPerHour` (RPH)

- Si el usuario lo proporciona en el request: se usa ese valor.
- Si es 0 o negativo: se usa el `defaultRPH` del `CostEstimator` (configurable vía `finops.default_requests_per_hour` en YAML, default: **1000**).

### 2.3. Fórmulas por Patrón

#### N+1 Query
```
MonthlyCost = 100 queries × RPH × 730 hr/month × $0.000001/read
```
- Supone **100 iteraciones** promedio por request (tamaño de colección iterada).
- Ejemplo: RPH=1000 → 100 × 1000 × 730 × 0.000001 = **$73.00/mes**

#### Unpaginated Scan
```
MonthlyCost = 10,000 items × RPH × 730 hr/month × $0.0000025/item
```
- Supone tabla con **10,000 items** que se leen en cada scan.
- Ejemplo: RPH=1000 → 10000 × 1000 × 730 × 0.0000025 = **$18,250.00/mes**

#### Lambda sin MemorySize
```
MonthlyCost = 256MB excess × RPH × 730 hr/month × $0.0000000163/MB-s
```
- Supone que sin configurar se asignan 512MB, y lo óptimo serían 256MB (exceso = 256MB).
- Ejemplo: RPH=1000 → 256 × 1000 × 730 × 0.0000000163 = **$3.05/mes**

#### Lambda sin Timeout
```
MonthlyCost = RPH × 730 hr/month × 5% risk × $0.0000166667/GB-s
```
- Factor de riesgo del 5% de ejecuciones runaway.
- Ejemplo: RPH=1000 → 1000 × 730 × 0.05 × 0.0000166667 = **$0.61/mes**

### 2.4. Propiedades del Estimador

- **Determinista:** Mismo input → mismo output.
- **Lineal en RPH:** El costo es directamente proporcional a RPH (2× RPH = 2× costo).
- **Redondeado:** Todos los costos se redondean a 2 decimales con `math.Round(v*100)/100`.
- **Patrón desconocido:** Retorna costo $0.00 con formula `"unknown pattern type"`.

---

## 3. Handler MCP (`handler.go`)

### 3.1. Esquema de Entrada (Input Schema)

```json
{
  "type": "object",
  "properties": {
    "source_code": {
      "type": "string",
      "description": "The Go source code to analyze for expensive patterns."
    },
    "file_path": {
      "type": "string",
      "description": "The file path of the source code being analyzed."
    },
    "requests_per_hour": {
      "type": "integer",
      "description": "Estimated execution frequency in requests per hour. Defaults to 1000 if not provided."
    }
  },
  "required": ["source_code", "file_path"]
}
```

### 3.2. Esquema de Salida

```json
{
  "findings": [
    {
      "pattern_type": "n_plus_1_query",
      "file_path": "main.go",
      "line_number": 7,
      "estimated_monthly_cost_usd": 73.00,
      "explanation": "This loop contains a database call...",
      "formula": "100 queries × 1000/hr × 730 hr/month × $0.000001/read"
    }
  ],
  "total_estimated_monthly_cost_usd": 73.00,
  "message": "Analyzed source, found 1 expensive pattern(s) with total estimated cost of $73.00/month"
}
```

### 3.3. Flujo de Ejecución

```
1. Parsear JSON params → FinOpsInput
2. Validar que source_code no esté vacío (error si lo está)
3. Llamar detector.DetectFromSource(source, filePath)
   └─ Parsea AST, recorre nodos, retorna []DetectedPattern
4. Para cada patrón detectado:
   a. estimator.Estimate(pattern, requestsPerHour) → CostEstimate
   b. generateExplanation(ctx, pattern, estimate, rph) → string
   c. Construir CostFinding
5. Sumar todos los costos → TotalCost (redondeado a 2 decimales)
6. Retornar FinOpsOutput con findings, total y mensaje
```

### 3.4. Generación de Explicaciones

El handler implementa un patrón **LLM-first con fallback heurístico:**

1. **Si `llm != nil`:** Construye un `Prompt{System: "template:finops_explanation", User: ...}` con los datos del hallazgo y llama a `llm.Complete(ctx, prompt)`.
2. **Si LLM falla o es nil:** Usa mensajes heurísticos específicos por tipo de patrón, que incluyen montos en dólares concretos y el RPH utilizado.

| Patrón | Mensaje Heurístico (template) |
|--------|-------------------------------|
| `n_plus_1_query` | "This loop contains a database call that creates an N+1 query pattern. At {rph} requests/hr, this could cost ~${cost}/month..." |
| `unpaginated_scan` | "This DynamoDB scan has no Limit field and will read all items in the table. At {rph} requests/hr, this could cost ~${cost}/month..." |
| `lambda_no_memory` | "This Lambda function has no MemorySize configured and will default to a potentially over-provisioned value..." |
| `lambda_no_timeout` | "This Lambda function has no Timeout configured, risking runaway executions..." |
| default | "Expensive pattern detected. Estimated cost: ~${cost}/month at {rph} requests/hr." |

### 3.5. Registro en el Dispatcher

```go
func RegisterFinOps(d *rpc.Dispatcher, handler *FinOpsHandler) {
    d.Register("finops/analyze", handler.Handle)
}
```

Se invoca desde `main.go` con:
```go
detector := finops.NewPatternDetector()
estimator := finops.NewCostEstimator(cfg.FinOps.DefaultRPH)
finopsHandler := finops.NewFinOpsHandler(detector, estimator, llmBackend)
finops.RegisterFinOps(dispatcher, finopsHandler)
```

---

## 4. Configuración

Definida en `internal/config/config.go`:

```yaml
finops:
  default_requests_per_hour: 1000  # baseline RPH cuando el request no lo provee
```

Validación: `DefaultRPH` debe ser > 0 (error de validación si es < 1).

---

## 5. Integración con el Sistema

### 5.1. Dependencias Internas

| Dependencia | Uso |
|-------------|-----|
| `internal/rpc.Dispatcher` | Registro del handler como tool MCP |
| `internal/llm.LLMBackend` | Generación de explicaciones (opcional, puede ser nil) |
| `internal/config.FinOpsConfig` | Configuración de RPH por defecto |

### 5.2. Declaración MCP en `tools/list`

Registrada en `internal/rpc/mcp.go` dentro de `mcpTools()`:
```go
{
    Name:        "finops/analyze",
    Description: "Detect expensive code patterns (N+1 queries, unpaginated DynamoDB scans, Lambda misconfigurations) and estimate their monthly AWS cost.",
    InputSchema: { ... }
}
```

---

## 6. Manejo de Errores

| Escenario | Comportamiento |
|-----------|----------------|
| JSON inválido en params | Retorna error `"invalid params: ..."` |
| `source_code` vacío | Retorna error `"invalid params: source_code is required"` |
| Código Go con errores de sintaxis | Retorna error `"failed to analyze source: ..."` |
| LLM falla (timeout, error) | Fallback silencioso a explicación heurística |
| Panic en handler | Recuperado por el Dispatcher → error interno -32603 |

---

## 7. Cobertura de Tests

Los tests existentes (`*_test.go`) cubren:

### detector_test.go
- N+1 en `for` loop y `range` loop
- Unpaginated `Scan` y `Query` (con y sin `Limit`)
- Lambda sin `MemorySize`, sin `Timeout`, ambos faltantes, y ambos presentes
- Código limpio sin patrones
- Código Go inválido (retorna error)
- Scan no-DynamoDB (no genera falso positivo)
- `Exec` dentro de loop

### estimator_test.go
- Default RPH cuando se pasa 0 o negativo
- Costo positivo para cada tipo de patrón
- Determinismo (mismo input → mismo output)
- Costo proporcional a RPH (2× RPH ≈ 2× costo)
- Valores exactos de fórmula verificados numéricamente
- Patrón desconocido → costo 0

### handler_test.go
- Detección end-to-end (N+1, Lambda, clean code)
- Validación de input vacío y JSON malformado
- Código Go inválido propagado como error
- Default RPH cuando no se provee
- LLM backend mockado (respuesta exitosa)
- Fallback a heurístico cuando LLM falla
- TotalCost = suma de findings individuales
- Explicaciones heurísticas contienen montos en `$`
- Registro en Dispatcher y dispatching de requests
- Método desconocido retorna -32601

---

## 8. Diagrama de Secuencia

```
MCP Client           Dispatcher         FinOpsHandler       Detector         Estimator       LLM
    │                    │                    │                │                │              │
    │─ finops/analyze ──►│                    │                │                │              │
    │                    │─── Handle(params) ►│                │                │              │
    │                    │                    │─ DetectFromSource() ─►│          │              │
    │                    │                    │◄── []DetectedPattern──│          │              │
    │                    │                    │                │                │              │
    │                    │                    │── Estimate(pattern) ──────────►│              │
    │                    │                    │◄── CostEstimate ──────────────│              │
    │                    │                    │                │                │              │
    │                    │                    │── Complete(prompt) ─────────────────────────►│
    │                    │                    │◄── LLMResponse (o error) ───────────────────│
    │                    │                    │                │                │              │
    │                    │◄── FinOpsOutput ───│                │                │              │
    │◄── JSON-RPC resp ──│                    │                │                │              │
```

---

## 9. Extensibilidad Futura

El diseño permite agregar nuevos patrones de costo con cambios mínimos:

1. **Nuevo `PatternType`** → Agregar constante en `detector.go`
2. **Nueva regla de detección** → Agregar case en `ast.Inspect` dentro de `DetectFromSource`
3. **Nueva fórmula** → Agregar método `estimate*` en `estimator.go` y case en `Estimate()`
4. **Nuevo mensaje heurístico** → Agregar case en `generateExplanation()` del handler

Patrones candidatos para futuras iteraciones:
- S3 `GetObject` sin caching (costos de transferencia)
- SQS polling agresivo sin backoff
- CloudWatch `PutMetricData` con alta cardinalidad
- API Gateway sin throttling configurado
