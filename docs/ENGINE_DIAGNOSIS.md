# ENGINE_DIAGNOSIS — Diagnóstico del motor 1.x y de sus puntuaciones

> **DOCUMENTO HISTÓRICO.** Diagnóstico del motor 1.x hecho al crear el Engine 2.0. Las anomalías descritas siguen siendo ciertas para el motor antiguo; las cifras del Engine 2.0 son las de aquel momento. Pesos, severidades y resultados vigentes: `SCORING_MODEL.md`, `CHECK_CATALOG.md` y `TESTING_REPORT.md`.

**Fecha:** 15 de noviembre de 2026 · **Alcance:** motor de análisis y scoring (no es una tercera auditoría de seguridad).

Todas las anomalías de este documento están **reproducidas** en el laboratorio (`tests/lab/lab.test.ts`), que ejecuta el motor 1.x congelado (`lib/audit/`) y el Engine 2.0 (`lib/engine/`) contra el mismo sitio simulado. Los identificadores `sNN` remiten a esos escenarios; las cifras salen de `tests/lab/results.json`.

---

## 1. Comprobación de continuidad

Ejecutado en este equipo (Windows 11, Node 24.14.1) **antes de tocar el código**:

| Comprobación | Resultado |
|---|---|
| `npm ci` | Necesario: `node_modules` no tenía las dependencias de desarrollo (vitest, typescript). Instalado desde el lockfile sin cambios. |
| `vitest run` | **222 / 222** tests (10 ficheros). Coincide con la cifra histórica. |
| `tsc --noEmit` | Sin errores. |
| `eslint` | Sin errores. |
| `npm audit` | 0 vulnerabilidades. |

Presencia en el código de las correcciones descritas en las auditorías 1 y 2:

| Corrección | Dónde | Estado |
|---|---|---|
| Bloqueo de IP privadas, loopback, metadata, CGNAT, rangos IPv6 | `lib/audit/ipGuard.ts` | Presente |
| Validación de URL, puertos 80/443, sin credenciales | `assertAllowedTarget`, `lib/normalizeUrl.ts` | Presente |
| DNS guardado (misma resolución para validar y conectar) | `createGuardedLookup` | Presente |
| Comparación de `socket.remoteAddress` con las IP aprobadas | `createPeerGuard` (antes dentro de `requestHeaders`) | Presente, ahora compartida por todas las conexiones |
| Revalidación en cada redirección, `agent: false` | `safeFetch` | Presente |
| Timeouts 8 s por petición / 20 s por análisis, `maxDuration = 30` | `safeRequest.ts`, `run.ts`, `route.ts` | Presente |
| Rate limiting 10/min cliente y 120/min global, Upstash opcional, hash de IP, /64 | `lib/rateLimit.ts`, `lib/analyzeRateLimit.ts`, `lib/clientIp.ts` | Presente (sin cambios) |
| CSP con nonce por petición, proxy, 404 propia | `proxy.ts`, `lib/csp.ts` | Presente (sin cambios) |
| Override de `minimatch` | `package.json` | Presente |

No se ha encontrado ninguna regresión respecto a lo documentado. **Nada de esto se ha podido verificar en la infraestructura real de Vercel** (ver `HANDOFF.md`).

---

## 2. Cómo funcionaba el motor 1.x

- Dos peticiones en serie: `GET` a la URL (solo cabeceras) y `GET` a `http://host/`.
- 8 checks fijos, todos basados en cabeceras de **esa única respuesta**, sea cual sea su código HTTP o su tipo de contenido.
- 3 estados: `pass` (100 % del peso), `warn` (50 %), `fail` (0 %).
- Puntuación = suma ponderada sobre 88 puntos, normalizada a 100.

Pesos: HTTPS 20 · redirección 10 · HSTS 10 · CSP 12 · iframes 10 · nosniff 10 · Referrer-Policy 8 · Permissions-Policy 8.

El diseño tiene una limitación de fondo: **solo sabe decir "bien", "a medias" o "mal"**. No puede expresar "no aplica", "no lo he podido comprobar" ni "esto no es tu web, es una página de error". Todo lo que no encaja se convierte en `warn` o `fail`, es decir, en puntos perdidos.

---

## 3. Anomalías reproducidas

### A1 — Una página de bloqueo o de error se puntúa como si fuera el sitio

**Causa:** el motor evalúa las cabeceras de la respuesta final sin mirar qué es esa respuesta.

| Escenario | Motor 1.x | Engine 2.0 |
|---|---|---|
| s10 · WAF/CDN bloquea al analizador (403 con *challenge*) | **39** «Débil» | Sin puntuación, cobertura 34 %, 0 fallos |
| s11 · HTTP 429 | **39** | Sin puntuación, 0 fallos |
| s15 · HTTP 503 temporal | **39** | Sin puntuación, 0 fallos |

Es probablemente la causa principal de las «puntuaciones extrañas» en webs reales: cualquier sitio detrás de Cloudflare, Akamai o similar que desafíe a clientes automatizados recibía ~39 con independencia de su configuración real. La nota medía la página de bloqueo de la CDN.

**Corrección:** la respuesta se clasifica (`ok`, `client-error`, `auth-required`, `rate-limited`, `server-error`, `blocked`). Con `blocked`, 429 o 5xx los controles que dependen de la respuesta pasan a `NOT_TESTED`; solo se evalúa lo que sigue siendo cierto (HTTPS, certificado, versión TLS). Con cobertura < 50 % no se publica cifra.

### A2 — Una API se juzga como si fuera una página HTML

**Causa:** CSP, protección de iframes, Referrer-Policy y Permissions-Policy solo tienen sentido en documentos que el navegador renderiza, pero se exigían a cualquier respuesta.

| Escenario | Motor 1.x | Engine 2.0 |
|---|---|---|
| s09 · API JSON que responde 401 con HSTS y nosniff | **61** | **100** (4 controles `NOT_APPLICABLE`) |
| s09b · API JSON 403 sin nosniff ni HSTS | **39** | **78** (2 fallos reales, confianza media) |

### A3 — Un certificado inválido produce un error, no un informe

**Causa:** la petición se hace con validación estricta; si el certificado falla, el análisis aborta con `TLS_ERROR` (HTTP 502).

| Escenario | Motor 1.x | Engine 2.0 |
|---|---|---|
| s03 · certificado caducado | `error TLS_ERROR` | **30** (tope), fallo crítico con fechas y emisor como evidencia |
| s03b · certificado de otro dominio | `error TLS_ERROR` | **30** (tope) |
| s03c · autofirmado | `error TLS_ERROR` | **30** (tope) |

Un certificado caducado es el hallazgo más grave que puede tener una web y el escáner no era capaz de informarlo.

### A4 — Una web sin HTTPS recibe mejor nota que una con HTTPS

**Causa doble:** (a) la falta de HTTPS se castigaba tres veces (HTTPS, HSTS y redirección: 40 de 88 puntos por una sola causa raíz) pero **sin tope**, y (b) el resto de cabeceras seguía sumando.

| Escenario | Motor 1.x | Engine 2.0 |
|---|---|---|
| s17 · web solo HTTP con buenas cabeceras | **55** «Mejorable» | **35** (tope), nota F |
| s02 · HTTPS correcto sin cabeceras | **39** «Débil» | **58**, nota D |

El orden estaba invertido: el sitio que envía todo en claro quedaba 16 puntos por encima del que cifra correctamente.

**Corrección:** una única penalización por la causa raíz (los controles derivados pasan a `NOT_APPLICABLE`) más un tope de 35 que impide que otros aciertos la diluyan.

### A5 — Si `https://` no responde, el análisis falla aunque la web exista

**Causa:** al escribir `midominio.com` se asume `https://`. Si el puerto 443 está cerrado, el motor devuelve «No se pudo conectar» en vez de informar de que la web no tiene HTTPS.

| Escenario | Motor 1.x | Engine 2.0 |
|---|---|---|
| s17b · 443 cerrado, 80 abierto | `error UNREACHABLE` | Informe con «HTTPS disponible» en fallo (evidencia: `ECONNREFUSED`), 35 |

### A6 — Cabeceras duplicadas por CDN + origen se interpretan como inválidas

**Causa:** cuando el origen y la CDN añaden la misma cabecera, Node las une con comas (`max-age=31536000, max-age=31536000`). La expresión regular de HSTS no encontraba un `max-age` válido y `X-Frame-Options: SAMEORIGIN, SAMEORIGIN` no coincidía con ningún valor conocido.

| Escenario | Motor 1.x | Engine 2.0 |
|---|---|---|
| s05c · HSTS, XFO y nosniff duplicados | **83** (HSTS `fail`, iframes `warn`) | **100** |

**Corrección:** HSTS usa la primera cabecera (RFC 6797 §8.1); X-Frame-Options acepta valores repetidos idénticos y solo avisa si son contradictorios.

### A7 — Una comprobación que no se pudo completar resta puntos

**Causa:** si `http://` no respondía, el check de redirección quedaba en `warn` (−5 puntos de 88).

| Escenario | Motor 1.x | Engine 2.0 |
|---|---|---|
| s15b · `http://` no responde (timeout) | **94** | **100**, redirección `NOT_TESTED`, cobertura 92 % |
| s16 · puerto 80 cerrado | **94** («no se ha podido confirmar») | **100**: un puerto 80 cerrado es correcto, no hay versión insegura |

### A8 — Una CSP declarada en `<meta>` no cuenta

**Causa:** solo se miraba la cabecera. En hostings estáticos sin control de cabeceras (GitHub Pages, por ejemplo) `<meta http-equiv="Content-Security-Policy">` es la única forma de tener CSP, y el navegador la aplica.

| Escenario | Motor 1.x | Engine 2.0 |
|---|---|---|
| s04d · CSP en `<meta>` | **75** (CSP `fail`) | **92** (CSP `pass`; clickjacking sigue en fallo porque `frame-ancestors` no funciona en `<meta>`) |

### A9 — Pesos que no reflejan el riesgo

- `Permissions-Policy` (8) pesaba casi lo mismo que CSP (12), y solo se comprobaba que **existiera**.
- `Referrer-Policy` ausente restaba 4 puntos, aunque todos los navegadores actuales aplican por defecto `strict-origin-when-cross-origin`.
- `warn` valía siempre el 50 %: una CSP en Report-Only (no bloquea nada) puntuaba igual que una CSP aplicada con `'unsafe-inline'`.

### A10 — Sitios con problemas reales obtienen 100

El motor no miraba cookies, CORS, contenido ni TLS, así que estos casos puntuaban **100**:

| Escenario | Motor 1.x | Engine 2.0 |
|---|---|---|
| s06 · cookie de sesión sin Secure ni HttpOnly | 100 | 89 (B) |
| s07 · CORS que refleja cualquier origen con credenciales | 100 | 89 (tope por severidad alta) |
| s18 · scripts por `http://` y formulario con contraseña enviado por HTTP | 100 | 86 (B) |
| s20 · servidor que acepta TLS 1.0 | 100 | 96 |

### A11 — Un solo número, sin contexto

No había cobertura, confianza, severidad ni evidencia. El usuario no podía saber por qué tenía esa nota, ni si el análisis había visto su web o una página de error. Los umbrales del texto resumen (`buildSummary`) y los de la etiqueta de color de la interfaz estaban duplicados en dos sitios.

---

## 4. Lo que **no** era un error

Para no sobrecorregir, se comprobó que estos comportamientos del motor 1.x eran correctos y se han conservado:

- `frame-ancestors` estricto sin `X-Frame-Options` ya se daba por bueno (s14).
- HSTS con `max-age=0`, `X-Content-Type-Options` con valor distinto de `nosniff` y CSP solo en Report-Only ya se trataban como no efectivos.
- Con `'nonce-…'` o `'strict-dynamic'`, `'unsafe-inline'` no se considera debilidad.

---

## 5. Problema nuevo detectado durante el trabajo

**Lectura del cuerpo de la respuesta.** El motor 1.x cortaba la conexión tras las cabeceras, así que nunca procesaba contenido del sitio. El Engine 2.0 lee hasta 512 KB de HTML para analizar contenido mixto, formularios y SRI, lo que introduce una superficie que antes no existía: un sitio malicioso puede responder con un cuerpo comprimido que se expande a gigabytes («bomba de compresión») para agotar la memoria de la función.

No estaba cubierto en las auditorías anteriores porque el código que lo hace posible no existía. Mitigación implementada: límite de bytes leídos, límite de salida al descomprimir (4 MB, `maxOutputLength`) y descarte silencioso del cuerpo si se supera. Test: `tests/engine/transport.test.ts` («no revienta con una bomba de compresión», 64 MB comprimidos).

---

## 6. Cómo reproducir

```bash
npm run test:lab
```

Para regenerar la tabla comparativa (`tests/lab/results.json`), en Git Bash:

```bash
LAB_REPORT=1 npx vitest run tests/lab
```
