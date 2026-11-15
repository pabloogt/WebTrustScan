# SCORING_MODEL — Cómo se calcula la puntuación

**Actualizado:** 15 de noviembre de 2026 (revisión técnica). Implementación: `lib/engine/scoring.ts` · Pesos: `lib/engine/catalog.ts` · Textos que ve el usuario: `lib/engine/format.ts` · Tests: `tests/engine/scoring.test.ts`, `revision.test.ts`, `calibration.test.ts`.

## 1. Las siete cifras del informe y qué significa cada una

| Cifra | Qué es | Qué **no** es |
|---|---|---|
| **Controles evaluados** | Controles con peso que terminaron en correcto, mejorable o fallo. | No incluye los informativos, los que no aplican ni los no comprobados. |
| **Controles correctos** («N de M correctos») | Recuento simple: de los M evaluados, cuántos están bien. | No es la puntuación. |
| **No aplican** | Controles sin sentido para esta web (p. ej. cookies en una web que no establece ninguna). No suman ni restan. | No son fallos ni aciertos. |
| **No comprobados** | Controles que el análisis no pudo evaluar (bloqueo, error temporal, sonda sin respuesta). No restan puntos. | No indican un problema de la web. |
| **Puntuación ponderada** | Peso conseguido entre peso evaluado, de 0 a 100. | **No es el porcentaje de controles correctos.** |
| **Cobertura del catálogo aplicable** | Parte, en peso, de los controles aplicables de este catálogo que se pudieron evaluar. | **No es el porcentaje de la seguridad del dominio que se ha auditado.** Un 100 % significa «se evaluó todo lo que este análisis sabe comprobar». |
| **Confianza** | Cuánto se apoya el resultado en pruebas directas y no en indicios. | No mide la gravedad. |

### Por qué «1 de 4 correctos» puede ser 9/100

Caso real (TermLifePicks, categoría «Protecciones del navegador»):

| Control | Peso | Resultado | Peso conseguido |
|---|---|---|---|
| Content-Security-Policy | 10 | Fallo | 0 |
| Protección frente a clickjacking | 6 | Fallo | 0 |
| X-Content-Type-Options | 4 | Fallo | 0 |
| Permissions-Policy | 2 | Correcto | 2 |
| **Total** | **22** | 1 de 4 correctos (25 %) | **2 → 2 / 22 = 9/100** |

El único control que pasa es el de menor peso. Por eso el informe muestra ambas cifras con su nombre: «1 de 4 correctos · puntuación ponderada 9/100». Un test fija este ejemplo.

## 2. Estados

| Estado | Significado | ¿Puntúa? |
|---|---|---|
| `pass` | Evaluado y correcto | Sí, 100 % del peso |
| `warning` | Presente pero parcialmente eficaz | Sí, con el *crédito* que fija el control (0–1) |
| `fail` | Ausente o sin efecto | Sí, 0 % |
| `info` | Dato útil, ni bueno ni malo | No |
| `not_applicable` | No tiene sentido para este sitio | No |
| `not_tested` | No se pudo comprobar por causas ajenas al sitio | No (reduce la cobertura) |
| `error` | Falló el propio análisis | No (reduce la cobertura) |

## 3. Fórmula

Sobre los hallazgos con peso > 0 y estado `pass`, `warning` o `fail`:

```
perdido(h)    = peso(h) × (1 − crédito(h)) × factorConfianza(h)
conseguido(h) = peso(h) − perdido(h)
bruta         = 100 × Σ conseguido / Σ peso
puntuación    = min(bruta, tope)
```

- `crédito`: 1 en `pass`, 0 en `fail`, el valor del control en `warning`.
- `factorConfianza`: alta 1 · media 0,75 · baja 0,5. Un indicio penaliza menos que un hecho.
- **Cobertura** = Σ peso evaluado / Σ peso (evaluado + no comprobado).
- **Confianza global** = media ponderada del factor de confianza × cobertura. Alta ≥ 0,85 · media ≥ 0,60 · baja el resto.
- **Notas:** A ≥ 90 · B ≥ 75 · C ≥ 60 · D ≥ 40 · F < 40.

### Cuándo no se publica una cifra

| Condición | Resultado |
|---|---|
| Cobertura < 50 % | Sin puntuación (cobertura insuficiente) |
| Menos de 6 controles evaluados en «Seguridad web», o menos de 2 en «Correo y DNS» | Sin puntuación (demasiado pocos controles) |
| Cobertura entre 50 % y 84 % | Puntuación marcada como **provisional** |
| Categoría con menos de 3 controles evaluados | Solo el recuento («1 de 1 correcto»), sin puntuación ponderada |

### Topes

| Condición | Tope |
|---|---|
| Certificado no válido | 30 |
| Sin HTTPS | 35 |
| Cualquier fallo de severidad **alta** con confianza **alta** | 89 |

El tope solo se declara si realmente ha rebajado la nota.

## 4. Pesos y severidades vigentes

La **severidad** describe el riesgo del hallazgo; el **peso**, cuánto cuenta el control en la nota de configuración. No son lo mismo: la ausencia de CSP es de severidad media (es una defensa en profundidad, no una vulnerabilidad) pero pesa 10, porque es la protección del navegador más importante.

| Control | Severidad máx. | Peso |
|---|---|---|
| `transport.https` | Crítica | 10 (tope 35) |
| `transport.certificate` | Crítica | 10 (tope 30) |
| `transport.hsts` | Media | 8 |
| `transport.http-redirect` | Media | 6 |
| `transport.tls-version` | Alta | 4 |
| `transport.legacy-tls` | Baja | 3 |
| `headers.csp` | Media | 10 |
| `headers.clickjacking` | Media | 6 |
| `headers.nosniff` | Baja | 4 |
| `headers.referrer-policy` | Baja | 2 |
| `headers.permissions-policy` | Baja | 2 |
| `cookies.secure` | Media | 6 |
| `cookies.httponly` | Media | 6 |
| `cookies.samesite` | Baja | 3 |
| `cors.policy` | Alta | 4 |
| `content.insecure-forms` | Alta | 6 |
| `content.mixed-content` | Media | 4 |
| `content.sri` | Baja | 2 |
| `disclosure.banner` | Baja | 1 |
| `headers.cross-origin-isolation`, `disclosure.security-txt` | Informativa | 0 |
| `email.dmarc` | Media | 6 |
| `email.spf` | Media | 5 |
| `dns.caa` | Informativa | 0 |

### Créditos de los resultados parciales

| Control | Situación | Crédito |
|---|---|---|
| CSP | Solo en Report-Only | 0,20 |
| CSP | Aplicada pero sin control de scripts | 0,25 |
| CSP | Con `'unsafe-inline'` o comodines | 0,50 |
| CSP | Solo `'unsafe-eval'` | 0,85 |
| HSTS | `max-age` inferior a 6 meses | 0,50 |
| Certificado | Próximo a caducar | 0,60 |
| Cookies | Cookies que no parecen de sesión sin `Secure` | 0,60 |
| Cookies | Posible cookie de sesión sin `SameSite` | 0,50 |
| DMARC | `p=none` con dirección de informes | 0,40 |
| DMARC | `p=none` sin dirección de informes | 0,25 |
| DMARC | `quarantine`/`reject` con `pct` < 100 | 0,80 |
| SPF | `?all` | 0,40 |
| SRI | Parte de los recursos con versión fija sin `integrity` | Proporción con `integrity` |

## 5. Justificación de las dos puntuaciones reales

### www.amazon.es — 82 (B)

17 controles evaluados, que suman 93 puntos de peso. Se pierden 16,65:

| Hallazgo | Peso | Crédito | Confianza | Puntos perdidos |
|---|---|---|---|---|
| CSP aplicada sin control de scripts | 10 | 0,25 | Alta | 10 × 0,75 = 7,5 |
| TLS 1.0 y 1.1 aceptados | 3 | 0 | Alta | 3,0 |
| Posible cookie de sesión sin HttpOnly | 6 | 0 | Baja (×0,5) | 6 × 0,5 = 3,0 |
| Cookies de preferencias sin Secure | 6 | 0,60 | Alta | 6 × 0,4 = 2,4 |
| Posible cookie de sesión sin SameSite | 3 | 0,50 | Baja (×0,5) | 1,5 × 0,5 = 0,75 |

(93 − 16,65) / 93 = 82. Si los dos hallazgos de cookies de sesión fueran hechos comprobados y no indicios, se perderían 20,4 puntos y la nota sería 78.

### termlifepicks.com — 61 (C)

13 controles evaluados, 72 puntos de peso. Se pierden 28:

| Hallazgo | Peso | Puntos perdidos |
|---|---|---|
| Sin CSP | 10 | 10 |
| Sin HSTS | 8 | 8 |
| Sin protección frente a clickjacking | 6 | 6 |
| Sin X-Content-Type-Options | 4 | 4 |

(72 − 28) / 72 = 61. SRI no puntúa: los dos scripts de terceros son servicios de contenido cambiante.

## 6. Revisión de la fórmula (15-11-2026)

Se revisó el cálculo en busca de errores. **No se ha encontrado ninguno en la fórmula ni se ha cambiado ningún peso en esta revisión.** Lo que se ha corregido es la presentación: la puntuación ponderada de una categoría aparecía junto al recuento sin nombre, y podía leerse como un porcentaje de controles superados.

Un test recalcula la puntuación de un informe a partir de sus hallazgos (peso × crédito) y comprueba que coincide con la que publica el motor.

Cambios de nota en esta revisión, todos por cambios en detecciones y no en pesos:

| Sitio | Antes | Ahora | Motivo |
|---|---|---|---|
| www.amazon.es | 85 | 82 | La cookie `session-id` vuelve a señalarse como posible cookie de sesión (confianza baja). La regla anterior exigía letras y cifras en el valor y descartaba identificadores solo numéricos: era demasiado permisiva. |
| termlifepicks.com | 61 | 61 | Sin cambios. |
| 31 escenarios de laboratorio | — | — | Idénticos antes y después. |

## 7. Limitaciones

- Los pesos son criterio experto contrastado con escenarios de laboratorio y dos sitios reales, no con datos de incidentes.
- Un sitio con pocos controles aplicables puede obtener una nota alta con poca superficie evaluada; por eso se muestra siempre el número de controles evaluados.
- La atenuación por confianza es una convención del modelo (0,75 y 0,5), no una magnitud medida.
- Las puntuaciones no son comparables con las de otras herramientas (Mozilla HTTP Observatory usa un modelo de penalizaciones y bonificaciones sobre 100).
