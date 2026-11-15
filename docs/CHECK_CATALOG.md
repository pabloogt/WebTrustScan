# CHECK_CATALOG — Catálogo de comprobaciones

Fuente de verdad en código: `lib/engine/catalog.ts` (identificador, categoría, severidad, peso, método y referencias). Un test garantiza que cada entrada del catálogo tiene exactamente una implementación.

Criterio general: **pocos controles, bien interpretados**. Un control entra si (1) se puede evaluar desde fuera con evidencia, (2) su resultado cambia lo que el dueño de la web debería hacer y (3) su tasa de falsos positivos es defendible.

## 1. Implementado (24 controles)

### Informe «Seguridad web»

| ID | Qué comprueba | Sev. máx. | Peso | Método |
|---|---|---|---|---|
| `transport.https` | La URL final se sirve por HTTPS. Si `https://` no responde, prueba `http://` e informa. | Crítica | 10 | Pasivo |
| `transport.certificate` | Cadena de confianza, nombre del host (SAN), vigencia y caducidad próxima (umbral proporcional a la duración del certificado). | Crítica | 10 | Pasivo |
| `transport.tls-version` | Versión TLS negociada ≥ 1.2. | Alta | 4 | Pasivo |
| `transport.legacy-tls` | El servidor rechaza un saludo TLS 1.0–1.1. | Media | 3 | Activo |
| `transport.http-redirect` | `http://` lleva a HTTPS del mismo sitio. Puerto 80 cerrado = correcto. | Alta | 6 | Activo |
| `transport.hsts` | `max-age` válido y ≥ 6 meses; avisa de `includeSubDomains` y de `preload` mal declarado. | Media | 8 | Pasivo |
| `headers.csp` | CSP aplicada (cabecera o `<meta>`), control real de scripts, `'unsafe-inline'`, comodines, `'unsafe-eval'`, Report-Only. | Alta | 10 | Pasivo |
| `headers.clickjacking` | `frame-ancestors` o X-Frame-Options (valores repetidos, contradictorios y obsoletos). | Media | 6 | Pasivo |
| `headers.nosniff` | `X-Content-Type-Options: nosniff`. | Baja | 4 | Pasivo |
| `headers.referrer-policy` | Valores que filtran la URL completa. Ausente = informativo. | Baja | 2 | Pasivo |
| `headers.permissions-policy` | Presencia y formato; detecta `Feature-Policy` obsoleta. | Baja | 2 | Pasivo |
| `headers.cross-origin-isolation` | COOP / COEP / CORP. | Info | 0 | Pasivo |
| `cookies.secure` | Atributo `Secure`; prefijos `__Host-` / `__Secure-`. | Media | 6 | Pasivo |
| `cookies.httponly` | `HttpOnly` en cookies que parecen de sesión (excluye tokens CSRF). | Media | 6 | Pasivo |
| `cookies.samesite` | `SameSite` declarado; `None` sin `Secure`. | Baja | 3 | Pasivo |
| `cors.policy` | Reflexión de origen, `null`, comodín con credenciales, `Vary: Origin`. | Alta | 4 | Activo |
| `content.mixed-content` | Recursos `http://` en página HTTPS (activos vs. pasivos; respeta `upgrade-insecure-requests`). | Media | 4 | Pasivo |
| `content.insecure-forms` | Formularios con `action` HTTP; agrava si llevan contraseña. | Alta | 6 | Pasivo |
| `content.sri` | Scripts y estilos de otros dominios sin `integrity`. | Baja | 2 | Pasivo |
| `disclosure.banner` | Versiones en `Server`, `X-Powered-By`, `X-AspNet-Version`, `X-Generator`. | Baja | 1 | Pasivo |
| `disclosure.security-txt` | `/.well-known/security.txt` válido y no caducado. | Info | 0 | Activo |

### Informe «DNS y correo» (puntuación independiente)

| ID | Qué comprueba | Sev. máx. | Peso |
|---|---|---|---|
| `email.spf` | Registro único, calificador de `all` (`+all`, `?all`, `~all`, `-all`), `redirect`. Sin MX ni SPF = informativo. | Media | 5 |
| `email.dmarc` | Existencia, política (`none` / `quarantine` / `reject`), `sp` heredado, `pct`. | Media | 6 |
| `dns.caa` | Registros `issue` / `issuewild`, con herencia del dominio padre. | Baja | 2 |

## 2. Evaluado para el catálogo: decisión y motivo

Valoración resumida de cada propuesta: utilidad · precisión · coste/complejidad · potencial comercial.

### Aprobado para el modo profundo (requiere dominio verificado — Pro)

| Módulo | Decisión | Motivo |
|---|---|---|
| **Ficheros y rutas sensibles** (`.git/HEAD`, `.env`, copias `.bak`/`.zip`, `phpinfo`, *source maps*) | **Siguiente módulo a construir** | Utilidad muy alta y precisión alta si se verifica el *contenido* de la respuesta, no solo el código 200. Lista cerrada (< 30 rutas). Es intrusivo-leve: solo con propiedad verificada. Es el argumento de venta más claro de Pro. |
| **Métodos HTTP** (`OPTIONS`, `TRACE`) | Aprobado | Barato y preciso. `TRACE` hoy es poco explotable: severidad baja. |
| **Rastreo limitado** (≤ 10 páginas del mismo dominio) | Aprobado | Mejora mucho contenido mixto, formularios y cookies, que hoy solo ven la portada. Coste: multiplica peticiones y tiempo → necesita cola, no una función síncrona. |
| **Listado de directorios** | Aprobado | Detección fiable por firma («Index of /»). |
| **Paneles de administración expuestos** | Aprobado como *informativo* | Que `/wp-admin` exista no es un fallo; solo se informa. |

### Aprobado para monitorización (Pro)

| Módulo | Decisión | Motivo |
|---|---|---|
| **Detección de cambios** entre auditorías | **Prioridad alta** | El motor ya produce resultados estables y con identificador: comparar dos informes es barato y es lo que justifica una suscripción. |
| **Caducidad de certificado** con aviso anticipado | Prioridad alta | El dato ya se recoge. Alerta de valor inmediato y cero falsos positivos. |
| **DNSSEC** | Aprobado, pendiente | `node:dns` no expone el bit AD ni consultas DS. Requiere DNS-over-HTTPS contra un resolvedor validador: dependencia externa nueva que hay que evaluar. |
| **DKIM** | Aprobado como *informativo* | Los selectores no se pueden enumerar. Solo se pueden probar selectores comunes: un «no encontrado» no demuestra nada, así que nunca puntuará. |
| **Certificate Transparency** (certificados emitidos para el dominio) | A estudiar | Buen valor para detectar emisiones inesperadas; depende de un servicio externo y de sus límites. |

### Pospuesto

| Módulo | Motivo |
|---|---|
| **Cifrados débiles / configuración TLS completa** | Requiere decenas de saludos por análisis. SSL Labs ya lo hace gratis y mejor; se enlazará en lugar de duplicarlo. |
| **`Cache-Control` en respuestas sensibles** | Solo tiene sentido en páginas autenticadas, que no vemos. En la portada genera ruido. |
| **`Clear-Site-Data`** | Solo aplica al cierre de sesión. |
| **Subdominios abandonados (*takeover*)** | Exige enumerar subdominios y verificar huellas por proveedor. Alto riesgo de falso positivo; nunca se declarará un *takeover* confirmado. Posible módulo Agency. |
| **WebSockets, seguridad de APIs** | Requieren conocer la aplicación o autenticarse. |

### Descartado

| Módulo | Motivo |
|---|---|
| **Correlación versión → CVE a partir de *banners*** | Precisión insuficiente: las distribuciones aplican parches sin cambiar la versión (*backports*), y muchos *banners* son falsos o de la CDN. Daría «vulnerabilidades» que no existen, justo lo que el producto quiere evitar. Solo se reconsiderará con evidencia de versión fiable (p. ej. un fichero de versión de un CMS en modo profundo) y mostrando siempre «indicio que requiere verificación». |
| **Detección de tecnologías como puntuación** | Informar de que una web usa WordPress no es un hallazgo de seguridad. Puede añadirse como dato informativo, nunca puntuado. |
| **`X-XSS-Protection`** | Cabecera obsoleta y retirada de los navegadores; pedirla es un error que cometen otros escáneres. |
| **`Expect-CT`, `Public-Key-Pins`** | Obsoletas. |
| **SEO y rendimiento** | Otro producto. Mezclarlo diluiría el posicionamiento. |

## 3. Cómo añadir un control

1. Añadir la definición en `lib/engine/catalog.ts` (ID, informe, categoría, severidad, peso, método, referencias).
2. Si necesita datos nuevos, recogerlos en `runAudit` (`lib/engine/run.ts`) **a través de `safeFetch` / `safeTlsProbe`** y exponerlos en `ScanContext`.
3. Implementar la función en `lib/engine/checks/<categoría>.ts` devolviendo un `Outcome` con `pass / fail / warning / info / notApplicable / notTested`. Usar `responseLevel` o `htmlOnly` si depende de la respuesta.
4. Añadir un escenario en `tests/lab/lab.test.ts` con el caso bueno, el malo y el «no aplica».
5. Justificar el peso en `SCORING_MODEL.md`.
