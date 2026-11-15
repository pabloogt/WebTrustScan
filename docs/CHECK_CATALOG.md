# CHECK_CATALOG — Catálogo de comprobaciones

**Actualizado:** 15 de noviembre de 2026. Fuente de verdad en código: `lib/engine/catalog.ts`. Un test garantiza que cada entrada tiene exactamente una implementación. Pesos y severidades: `SCORING_MODEL.md` §4.

Criterio: **pocos controles, bien interpretados**. Un control entra si se puede evaluar desde fuera con evidencia, si su resultado cambia lo que el dueño de la web debería hacer y si su tasa de falsos positivos es defendible.

## 1. Controles implementados (24)

### Informe «Seguridad web» (21)

| ID | Qué comprueba y cómo decide | Método |
|---|---|---|
| `transport.https` | La URL final se sirve por HTTPS. Si `https://` no responde prueba `http://` e informa. | Pasivo |
| `transport.certificate` | Cadena de confianza, nombre del host, vigencia y caducidad próxima. | Pasivo |
| `transport.tls-version` | Versión que negocia una conexión normal con un cliente actual. Avisa (sin penalizar) si el servidor no ofrece TLS 1.3. | Pasivo |
| `transport.legacy-tls` | **Un saludo independiente por versión** (TLS 1.0, 1.1, 1.2 y 1.3). Falla si acepta 1.0 o 1.1; indica cuál de las dos. | Activo |
| `transport.http-redirect` | `http://` lleva a HTTPS del mismo sitio. Puerto 80 cerrado = correcto. | Activo |
| `transport.hsts` | `max-age` válido y ≥ 6 meses. `includeSubDomains` y `preload` no se exigen ni se recomiendan como primer paso. | Pasivo |
| `headers.csp` | CSP **aplicada** (cabecera o `<meta>`) y con control real de scripts. Distingue Report-Only, sin `script-src`, `'unsafe-inline'`, comodines y `'unsafe-eval'`. | Pasivo |
| `headers.clickjacking` | `frame-ancestors` o X-Frame-Options. | Pasivo |
| `headers.nosniff` | `X-Content-Type-Options: nosniff`. | Pasivo |
| `headers.referrer-policy` | Valores que filtran la URL completa. Ausente = informativo. | Pasivo |
| `headers.permissions-policy` | Presencia y formato. | Pasivo |
| `headers.cross-origin-isolation` | COOP / COEP / CORP. Solo informativo. | Pasivo |
| `cookies.secure` | Atributo `Secure`. | Pasivo |
| `cookies.httponly` | `HttpOnly` en cookies que podrían ser de sesión. | Pasivo |
| `cookies.samesite` | `SameSite` declarado; `None` sin `Secure`. | Pasivo |
| `cors.policy` | Reflexión de origen, `null`, comodín con credenciales. | Activo |
| `content.mixed-content` | Recursos `http://` en página HTTPS. | Pasivo |
| `content.insecure-forms` | Formularios con `action` HTTP. | Pasivo |
| `content.sri` | `integrity` en scripts y estilos de terceros **con versión fija**. | Pasivo |
| `disclosure.banner` | Versiones de software en cabeceras. | Pasivo |
| `disclosure.security-txt` | `/.well-known/security.txt`. Solo informativo. | Activo |

### Informe «Correo y DNS» (3) — evaluación limitada

| ID | Qué comprueba | Peso |
|---|---|---|
| `email.spf` | Registro único y calificador de `all`: `+all` (falla), `?all` (parcial), `~all` softfail y `-all` fail (ambos correctos, descritos por separado). | 5 |
| `email.dmarc` | Existencia, política y `rua`. `p=none` se describe como «no solicita cuarentena ni rechazo», sin afirmar qué hará cada receptor. | 6 |
| `dns.caa` | Registros CAA. **Informativo y sin peso** cuando faltan: CAA es opcional. | 0 |

**Este informe solo mira dos registros DNS.** No comprueba DKIM, ni que los mensajes enviados superen SPF/DKIM/DMARC, ni DNSSEC, MTA-STS, TLS-RPT o los servidores de correo. La interfaz y el PDF lo advierten de forma visible. Con menos de dos controles evaluados no se publica nota.

## 2. Heurísticas: qué se deduce y con qué confianza

Varias conclusiones no se pueden demostrar desde fuera. Se señalan como indicio, con confianza reducida (que también reduce su peso en la nota) y sin afirmaciones categóricas.

| Decisión | Regla | Confianza | Riesgo conocido |
|---|---|---|---|
| ¿Es una cookie de sesión? | Nombre de sesión de un framework conocido (`PHPSESSID`, `JSESSIONID`…), **o** nombre sugerente (`sess`, `auth`, `token`…) y valor de 16 o más caracteres. Los tokens anti-CSRF se excluyen. | Media (nombre conocido) o baja (nombre sugerente) | Falso positivo: un identificador de visitante que no autentica (caso `session-id` de Amazon). Falso negativo: una cookie de sesión con nombre no reconocible. |
| ¿Es un borrado de cookie? | Valor vacío, `Max-Age` ≤ 0 o, si no hay `Max-Age`, `Expires` en el pasado. `Max-Age` tiene prioridad (RFC 6265). Una fecha ilegible no se toma por borrado. | Alta | — |
| ¿Dos cabeceras son la misma cookie? | Mismo nombre, dominio y ruta. | Alta | — |
| ¿Un recurso es propio? | Mismo dominio registrable (alta). O dominio cuyo nombre contiene la marca del sitio **como palabra completa** (`media-amazon`, `githubassets`), con marcas de 4 o más letras (indicio, se declara en el informe). | Alta / indicio | `shopify` ya no cuenta como propio de `shop`. Una organización con dominios de recursos sin relación de nombre se verá como tercero. |
| ¿Admite SRI un recurso de terceros? | **Versión fija:** número de versión o hash en la URL → se evalúa. **Servicio de contenido cambiante:** lista de dominios conocidos (analítica, publicidad, fuentes, pagos) → no puntúa. **Desconocido:** tercero sin versión visible → no puntúa y se dice que no se puede saber. | Media | La lista de servicios es finita. Un fichero fijo servido sin versión en la URL no se evalúa. |
| ¿Hay una CDN o WAF delante? | Cabeceras propias del proveedor (`cf-ray`, `x-amz-cf-id`, `x-vercel-id`…). | Alta para la presencia; no se afirma nada sobre el origen | Proveedores no listados no se detectan. |
| ¿La respuesta es un bloqueo? | Solo con 403, 429 o 503 **y** una marca específica del proveedor. Un 403 con texto genérico se evalúa como página de error normal. | Alta | Un bloqueo de un proveedor no listado se evalúa como 403 corriente, con confianza reducida. |
| ¿El sitio es WordPress? | Rutas `/wp-content/` o `/wp-includes/` en los recursos. Solo se usa para adaptar la recomendación de CSP. | Indicio («parece WordPress») | — |

## 3. DKIM: valorado, no implementado

Añadir DKIM tiene valor, pero «DKIM» son cuatro cosas distintas y solo las dos primeras son posibles sin acceso al correo del dominio:

| Nivel | Qué demuestra | ¿Posible desde fuera? |
|---|---|---|
| 1. Descubrimiento de selectores | Nada por sí solo. Los selectores no se pueden enumerar: solo se pueden probar nombres comunes (`google`, `selector1`, `default`, `k1`…). **No encontrar ninguno no significa que no haya DKIM.** | Parcial |
| 2. Existencia de un registro TXT en `<selector>._domainkey` | Que el dominio publica una clave para ese selector. | Sí |
| 3. Validez de la clave publicada | Que el registro es sintácticamente correcto y la clave tiene un tamaño aceptable (por ejemplo, RSA de 2048 bits) y no está revocada (`p=` vacío). | Sí |
| 4. Verificación efectiva | Que los mensajes que envía el dominio van firmados y la firma valida. | **No.** Hace falta recibir un mensaje real del dominio. |

Si se implementa, será **informativo y sin peso**, y el texto dirá «se ha encontrado una clave DKIM publicada para el selector X», nunca «DKIM verificado». El nivel 4 solo sería posible con un buzón de pruebas al que el usuario envíe un correo, que es otra funcionalidad.

## 4. Otras propuestas evaluadas

| Módulo | Decisión | Motivo |
|---|---|---|
| Ficheros y rutas sensibles (`.git`, `.env`, copias) | Aprobado, pospuesto | Requiere verificar la propiedad del dominio, que depende de las cuentas (hoy desactivadas). |
| Métodos HTTP, listado de directorios, rastreo limitado | Aprobado, pospuesto | Mismo requisito. |
| Detección de cambios y aviso de caducidad de certificado | Aprobado, pospuesto | Dependen de guardar auditorías. |
| DNSSEC | Pendiente | `node:dns` no expone lo necesario; exige DNS-over-HTTPS contra un servicio externo. |
| Cifrados TLS débiles | Pospuesto | Decenas de saludos por análisis; SSL Labs lo hace gratis. |
| Subdominios abandonados | Pospuesto | Alto riesgo de falso positivo. |
| Correlación versión → CVE a partir de *banners* | **Descartado** | Los *backports* y los *banners* falsos darían vulnerabilidades inexistentes. |
| `X-XSS-Protection`, `Expect-CT`, `Public-Key-Pins` | **Descartado** | Cabeceras obsoletas. |
| SEO y rendimiento | **Descartado** | Otro producto. |

## 5. Cómo añadir un control

1. Definirlo en `lib/engine/catalog.ts`.
2. Si necesita datos nuevos, recogerlos en `runAudit` **a través de `safeFetch` / `safeTlsProbe`** y exponerlos en `ScanContext`.
3. Implementarlo en `lib/engine/checks/<categoría>.ts`, decidiendo de forma explícita cuándo es `not_applicable`, `not_tested` o `info`, y con qué confianza.
4. Añadir al laboratorio el caso bueno, el malo, el «no aplica» y el falso positivo que se quiere evitar.
5. Justificar el peso en `SCORING_MODEL.md`.
