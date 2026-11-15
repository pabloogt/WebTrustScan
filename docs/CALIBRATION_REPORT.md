# CALIBRATION_REPORT — Calibración con dos análisis reales

**Actualizado:** 15 de noviembre de 2026 (segunda pasada: revisión técnica). **Casos:** `www.amazon.es` y `termlifepicks.com`.

Informes vigentes, en JSON y PDF: [`docs/informes/`](informes/). No se ha modificado nada en ninguno de los dos sitios; solo se han usado las comprobaciones inocuas del motor.

## Evolución de las puntuaciones

| Sitio | Motor 1.x | Engine 2.0 inicial | 1.ª calibración | **Revisión técnica** | Correo y DNS |
|---|---|---|---|---|---|
| www.amazon.es | 78 | 77 | 85 | **82 (B)** | 100 (A) |
| termlifepicks.com | 77 | 60 | 61 | **61 (C)** | 59 (D) |

El desglose de cada nota está en `SCORING_MODEL.md` §5.

## Primera calibración (resumen)

Corrigió tres errores del motor detectados con datos reales:

- **Cookies de borrado contadas como cookies.** Amazon envía cabeceras que borran cookies antiguas de otro dominio; el motor se quedaba con la última por nombre y veía una «cookie de sesión sin Secure» inexistente. Ahora las cookies se identifican por nombre + dominio + ruta y los borrados se ignoran.
- **CDN propio tratado como tercero.** `m.media-amazon.com` contaba como tercero para SRI.
- **SRI exigido a servicios que no lo admiten.** Google Tag Manager y AdSense se penalizaban.

Y cuatro criterios: CSP ausente pasa a severidad media; CAA ausente es informativo; DMARC distingue `p=none` con y sin informes; no se publica nota con muy pocos controles.

## Revisión técnica: qué se encontró y qué se cambió

### 1. TLS: la afirmación no se correspondía con la prueba

**Problema.** El informe decía «el servidor ha completado un saludo limitado a TLS 1.0–1.1» y mostraba un comando con `-tls1_1`. El motor hacía **un solo** saludo con el rango 1.0–1.1: el servidor elige la más alta que admite, así que el resultado «TLS 1.1» no decía nada sobre TLS 1.0. Además la frase podía leerse como que el servidor solo admite esas versiones.

**Cambio.** Un saludo independiente por versión (1.0, 1.1, 1.2, 1.3), cada uno limitado a esa única versión, más la versión que negocia una conexión normal. El informe enumera los cinco resultados y da un comando de reproducción por cada versión antigua aceptada.

**Tres resultados posibles por versión**, que antes se mezclaban:

| Resultado | Cuándo | Efecto |
|---|---|---|
| Aceptado | El saludo se completa | Hallazgo si es 1.0 o 1.1 |
| Rechazado | El servidor responde con una alerta de versión no admitida (concluyente) o corta el saludo sin explicación (coherente con un rechazo; confianza media) | Correcto |
| No comprobable | Fallo de red, tiempo agotado, destino bloqueado, servicio que no habla TLS o **cliente que no puede usar esa versión** | «No comprobado»: no se afirma nada del servidor |

Antes, un `ECONNRESET` o un fallo interno se contaban como rechazo, y el motor no distinguía un rechazo explícito de un corte.

**Resultado en `www.amazon.es`**, idéntico con el motor y con OpenSSL ejecutado aparte:

| Versión | Motor | `openssl s_client` |
|---|---|---|
| TLS 1.0 | Aceptado | Aceptado (`ECDHE-RSA-AES128-SHA`) |
| TLS 1.1 | Aceptado | Aceptado |
| TLS 1.2 | Aceptado | Aceptado |
| TLS 1.3 | Aceptado | Aceptado |
| Conexión normal | Negocia TLS 1.3 | Negocia TLS 1.3 |

Texto actual: «El servidor todavía acepta conexiones con TLS 1.0 y TLS 1.1 […]. Esto no cambia cómo conectan los navegadores actuales, que con este servidor negocian TLSv1.3: solo un cliente antiguo, o uno forzado a bajar de versión, usaría esas versiones.» Severidad baja.

`termlifepicks.com` rechaza 1.0 y 1.1 con una alerta explícita de versión de protocolo.

### 2. DMARC y SPF: se afirmaba lo que harían los receptores

**Problema.** Para `v=DMARC1; p=none;` el informe decía que los correos que suplantan el dominio «se siguen entregando». Eso depende de cada receptor, no del registro. SPF describía `~all` y `-all` de forma parecida.

**Cambio.**

- `p=none`: «el dominio no pide a los receptores que pongan en cuarentena ni rechacen los mensajes que fallan DMARC. Eso no significa que esos mensajes se entreguen siempre: cada receptor sigue aplicando sus propios filtros antispam y de seguridad».
- Sin `rua`: «el registro no especifica ninguna dirección a la que enviar los informes agregados de DMARC».
- `~all` se describe como **softfail** (pide aceptar y tratar como sospechoso) y `-all` como **fail** (pide rechazar). Ambos siguen siendo correctos; cambia la explicación, no la nota.
- `quarantine` y `reject` describen lo que el dominio **pide**, no lo que ocurrirá.

Severidad de `p=none` sin `rua`: baja, crédito 0,25 (sin cambios).

### 3. HSTS: se recomendaba `includeSubDomains` sin poder comprobarlo

**Problema.** La cabecera propuesta era `max-age=31536000; includeSubDomains`, y un HSTS sin esa opción se presentaba como mejorable.

**Cambio.** La recomendación es progresiva: empezar con un día, subir a un año cuando funcione, y añadir `includeSubDomains` **solo** tras verificar que todos los subdominios, actuales y previstos, funcionan por HTTPS; se explica que con esa opción el navegador deja de abrir por HTTP cualquier subdominio. `preload` no se recomienda. Un HSTS válido sin `includeSubDomains` es correcto sin reservas.

### 4. CSP: se proponía una política concreta para copiar

**Problema.** Se sugería `default-src 'self'; object-src 'none'…`, que en un WordPress con Tag Manager y AdSense rompería la web.

**Cambio.** La recomendación empieza siempre por `Content-Security-Policy-Report-Only`, revisar las infracciones y después aplicar. Nombra los terceros detectados en la página (en TermLifePicks: `googletagmanager.com`, `googlesyndication.com`) y, si el sitio parece WordPress, advierte de la plantilla y los plugins. Una política solo en Report-Only se describe como «no hay ninguna CSP aplicada».

### 5. Heurísticas: la primera calibración se había pasado de permisiva

| Heurística | Problema | Cambio |
|---|---|---|
| Cookie de sesión | Se exigía que el valor mezclara letras y cifras: un identificador solo numérico (el `session-id` de Amazon) o solo hexadecimal quedaba descartado. **Falso negativo.** | Basta un nombre sugerente y un valor de 16 o más caracteres. Sigue siendo un indicio, con confianza baja y el texto «Es un indicio, no una certeza». |
| Borrado de cookie | Se miraba `Expires` aunque hubiera `Max-Age`. | `Max-Age` tiene prioridad (RFC 6265); una fecha ilegible no se toma por borrado. |
| Recurso propio por marca | Bastaba que el nombre contuviera la marca: `cdn.shopify.com` se daba por propio de `shop.com`. **Falso negativo.** | La marca debe aparecer como palabra completa (`media-amazon`, `githubassets`). El informe declara qué dominios se han tratado como propios y que es un indicio. |
| Tercero sin versión en la URL | Se clasificaba como «dinámico, SRI no aplicable»: una afirmación sin base. | Clase aparte: «no se puede saber desde fuera si su contenido es fijo». No puntúa, pero se dice y se recomienda una URL versionada. |
| Bloqueo de WAF | El texto genérico «request unsuccessful» en un 403 se tomaba por bloqueo. | Solo cuentan marcas específicas de proveedor. |

**Efecto en Amazon:** la cookie `session-id` (con `Secure`, sin `HttpOnly` ni `SameSite`) vuelve a señalarse, ahora con confianza baja. Por eso la nota baja de 85 a 82. Es el único cambio de puntuación de esta revisión.

### 6. Presentación

- «N de M correctos · **puntuación ponderada** X/100», para que 9/100 no se lea como un 9 % de controles superados.
- «Cobertura **del catálogo aplicable**», con la aclaración de que no equivale a auditar el dominio.
- Apartado «Cómo leer estas cifras» en la interfaz y en el PDF.
- Aviso visible de **evaluación limitada** en el informe de correo y DNS.
- CAA ausente sigue siendo informativo y sin peso.

## Límites

Dos sitios no son una muestra. Las reglas de cookies, marca y SRI son heurísticas que fallarán en algún caso; por eso llevan confianza reducida y texto condicional. Hace falta repetir el ejercicio con 20–30 dominios autorizados antes de dar el motor por calibrado.
