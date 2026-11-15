# SCORING_MODEL — Modelo de puntuación del Engine 2.0

Implementación: `lib/engine/scoring.ts` · Pesos: `lib/engine/catalog.ts` · Tests: `tests/engine/scoring.test.ts` y `tests/lab/lab.test.ts`.

## 1. Principios

1. **Solo puntúa lo que se ha podido evaluar.** Un control no aplicable o no comprobado no suma ni resta.
2. **No comprobar no es fallar.** `NOT_TESTED` y `ERROR` reducen la *cobertura*, nunca la puntuación.
3. **Una causa raíz, una penalización.** Los controles que dependen de otro que ya ha fallado pasan a `NOT_APPLICABLE`.
4. **Los fallos críticos no se diluyen.** Un tope impide que otros aciertos tapen un certificado caducado.
5. **La duda penaliza menos.** Un hallazgo basado en una heurística resta menos que uno demostrado.
6. **Riesgos distintos, informes distintos.** Seguridad web y DNS/correo tienen puntuaciones independientes.
7. **La cifra no es una certificación.** Va siempre acompañada de cobertura, confianza y hallazgos.

## 2. Estados

| Estado | Significado | ¿Puntúa? |
|---|---|---|
| `pass` | Control evaluado y correcto | Sí, 100 % del peso |
| `warning` | Control presente pero parcialmente eficaz | Sí, con el *crédito* que fija el check (0–1) |
| `fail` | Control ausente o sin efecto | Sí, 0 % |
| `info` | Dato útil, ni bueno ni malo | No |
| `not_applicable` | No tiene sentido para este sitio | No |
| `not_tested` | No se pudo comprobar por causas ajenas al sitio | No (reduce cobertura) |
| `error` | Falló el propio análisis | No (reduce cobertura) |

`warning` no vale un porcentaje fijo. Ejemplos de CSP: solo Report-Only 0,20 · sin control de scripts 0,25 · con `'unsafe-inline'` o comodines 0,50 · solo `'unsafe-eval'` 0,85.

## 3. Fórmula

Para cada informe, sobre los hallazgos con estado `pass`, `warning` o `fail` y peso > 0:

```
perdido(h)     = peso(h) × (1 − crédito(h)) × factorConfianza(h)
conseguido(h)  = peso(h) − perdido(h)
bruta          = 100 × Σ conseguido / Σ peso
puntuación     = min(bruta, tope)          si cobertura ≥ 50 %
               = sin puntuación            si cobertura < 50 %
```

`factorConfianza`: alta 1 · media 0,75 · baja 0,5.

**Cobertura** = Σ peso evaluado / Σ peso (evaluado + `not_tested` + `error`). Mide cuánto se ha visto, no cuán segura es la web.

- Cobertura < 50 %: no se publica cifra («Sin puntuación»).
- Cobertura 50–84 %: cifra marcada como **provisional**.
- Cobertura ≥ 85 %: cifra normal.

**Confianza global** = media ponderada del factor de confianza × cobertura. Alta ≥ 0,85 · media ≥ 0,60 · baja el resto.

**Notas:** A ≥ 90 · B ≥ 75 · C ≥ 60 · D ≥ 40 · F < 40.

## 4. Topes

| Condición | Tope | Motivo |
|---|---|---|
| Certificado inválido (`transport.certificate` en fallo) | 30 | El navegador muestra una advertencia a pantalla completa; el resto de la configuración es irrelevante para el visitante. |
| Sin HTTPS (`transport.https` en fallo) | 35 | Todo viaja en claro; ninguna cabecera lo compensa. |
| Cualquier fallo de severidad **alta** con confianza **alta** | 89 | Un problema grave confirmado es incompatible con la nota A. |

Con varios topes se aplica el más bajo. El tope solo se declara en el informe si realmente ha rebajado la cifra.

## 5. Pesos del informe «Seguridad web»

Escala: crítico 10 · alto 4–10 · medio 3–8 · bajo 1–4 · informativo 0. El peso refleja el impacto si el control falta; dentro de una misma severidad pesa más el que protege frente a un ataque más directo.

| Control | Sev. | Peso | Justificación |
|---|---|---|---|
| `transport.https` | Crítica | 10 | Sin cifrado no hay confidencialidad ni integridad. Tope 35. |
| `transport.certificate` | Crítica | 10 | Un certificado inválido deja la web inutilizable y entrena al usuario a ignorar avisos. Tope 30. |
| `transport.hsts` | Media | 8 | Cierra el *downgrade* en la primera visita. Es el control de transporte que más webs omiten. |
| `transport.http-redirect` | Alta | 6 | Sin redirección, los enlaces `http://` antiguos se sirven en claro. |
| `transport.tls-version` | Alta | 4 | Negociar TLS < 1.2 es grave, pero hoy muy raro: peso moderado para no inflar la nota por algo que casi todos cumplen. |
| `transport.legacy-tls` | Media | 3 | Aceptar TLS 1.0/1.1 requiere un atacante activo y un cliente antiguo. |
| `headers.csp` | Alta | 10 | Principal mitigación de XSS, la vulnerabilidad web más común. |
| `headers.clickjacking` | Media | 6 | Ataque práctico pero que necesita interacción del usuario. |
| `headers.nosniff` | Baja | 4 | Mitigación barata; el riesgo real depende de que haya subida de ficheros. |
| `headers.referrer-policy` | Baja | 2 | El valor por defecto del navegador ya es seguro; solo se penalizan valores que filtran. |
| `headers.permissions-policy` | Baja | 2 | Defensa en profundidad; ausente no implica ningún ataque directo. |
| `cookies.secure` | Media | 6 | Una cookie de sesión sin Secure puede filtrarse por HTTP. |
| `cookies.httponly` | Media | 6 | Convierte un XSS en robo de sesión. |
| `cookies.samesite` | Baja | 3 | Chrome y Edge ya aplican `Lax` por defecto. |
| `cors.policy` | Alta | 4 | Peso bajo porque casi siempre es correcto; el caso grave lo cubre el tope de 89. |
| `content.insecure-forms` | Alta | 6 | Datos (o contraseñas) enviados en claro. |
| `content.mixed-content` | Media | 4 | Los navegadores ya bloquean el contenido activo; el daño principal es funcional. |
| `content.sri` | Baja | 2 | Riesgo de cadena de suministro; no siempre aplicable (scripts sin versión fija). |
| `disclosure.banner` | Baja | 1 | Facilita el reconocimiento, no es una vulnerabilidad. |
| `headers.cross-origin-isolation`, `disclosure.security-txt` | Info | 0 | Solo informativos. |

Informe «DNS y correo»: `email.dmarc` 6 · `email.spf` 5 · `dns.caa` 2.

### Comprobación de los pesos con escenarios

| Escenario | Resultado | Lectura |
|---|---|---|
| Todo correcto (s01) | 100 A | — |
| HTTPS impecable, ninguna cabecera (s02) | 58 D | El transporte está bien (41 de los 72 puntos aplicables) pero faltan todas las protecciones del navegador. |
| Solo falta HSTS, o HSTS `max-age=0` (s05) | 89 B | Un único control medio de peso 8 baja una nota. |
| CSP débil, resto perfecto (s04) | 93 A | Aviso de severidad media; no impide la A porque el control existe y limita parcialmente. |
| Cookie de sesión sin Secure ni HttpOnly (s06) | 89 B | Dos fallos medios con confianza media (heurística por nombre). |
| CORS con credenciales para cualquier origen (s07) | 89 B (tope) | Sin el tope sería 95: un fallo alto no puede convivir con una A. |
| Sin HTTPS (s17) | 35 F (tope) | Las cabeceras no compensan el canal en claro. |
| Certificado caducado (s03) | 30 F (tope) | Bruta > 80. |

## 6. Resolución de los escenarios pedidos

| Escenario | Tratamiento |
|---|---|
| CSP con `frame-ancestors` correcto y X-Frame-Options ausente | `headers.clickjacking` = `pass`. `frame-ancestors` sustituye a XFO; no se exige ambos. |
| CSP débil | `warning` con crédito graduado según la debilidad concreta, que se nombra en la descripción. |
| HSTS `max-age=0` | `fail`: la cabecera ordena al navegador olvidar la protección. |
| `X-Content-Type-Options` inválido | `fail`: solo `nosniff` tiene efecto. |
| Web sin cookies | Los tres controles de cookies = `not_applicable`. |
| API 401 / 403 | Se clasifica como `auth-required`; los controles de documento HTML = `not_applicable` si la respuesta no es HTML; lo que sí se evalúa lleva confianza media. |
| Cloudflare (u otra CDN) | Sitio normal: se evalúa y se avisa del intermediario. *Challenge* / bloqueo: controles de respuesta = `not_tested`, sin puntuación. |
| Varios dominios (redirección a otro host) | Se evalúa el destino final; la cadena queda registrada y visible. |
| SPA | Se evalúa lo que entrega el servidor y se avisa de que el contenido generado en el navegador no se ve. |
| Web estática / sin formularios | `content.insecure-forms` y, si no hay terceros, `content.sri` = `not_applicable`. CSP en `<meta>` cuenta. |
| Redirecciones múltiples | Hasta 5 saltos, cada uno revalidado contra SSRF. A partir de 3 se añade un aviso. |
| Errores temporales (5xx, 429, timeout de una sonda) | `not_tested`. Si falla la petición principal por completo, error explícito sin informe. |
| Respuesta de CDN distinta del origen | Aviso permanente cuando se detecta CDN: las cabeceras son las que ve un visitante; no se afirma nada sobre el origen. |

## 7. Penalizaciones duplicadas eliminadas

| Causa raíz | Controles que pasan a `not_applicable` |
|---|---|
| Sin HTTPS | certificado, versión TLS, TLS antiguo, redirección, HSTS, `cookies.secure`, contenido mixto, formularios inseguros |
| TLS negociado obsoleto | `transport.legacy-tls` |
| Protección de iframes | Un solo control para `frame-ancestors` y X-Frame-Options |

## 8. Relación con otros modelos

Mozilla HTTP Observatory parte de 100 y aplica penalizaciones y bonificaciones por test, con una puntuación máxima superior a 100 ([metodología en MDN](https://developer.mozilla.org/en-US/observatory/docs/tests_and_scoring)). WebTrustScan usa crédito ponderado sobre lo aplicable porque necesita tres cosas que un modelo puramente deductivo no ofrece: excluir controles no aplicables sin alterar la escala, separar cobertura de puntuación y atenuar por confianza. Las puntuaciones de ambas herramientas **no son comparables** entre sí.

## 9. Limitaciones conocidas

- Los pesos son criterio experto contrastado con escenarios de laboratorio, no con datos de incidentes reales. Deben revisarse cuando haya un corpus de webs reales autorizadas.
- Un sitio con pocos controles aplicables (una API mínima) puede obtener 100 con poca superficie evaluada. La cobertura no lo refleja, porque mide lo comprobado sobre lo aplicable; el número de controles evaluados sí se muestra por categoría.
- La clasificación «cookie de sesión» se basa en el nombre.
- La nota A con CSP débil (s04) es una decisión discutible; si se quiere más exigencia basta bajar el crédito de `weak` de 0,5 a 0,3.
