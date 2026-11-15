# SECURITY_METHODOLOGY — Metodología y estándares

## 1. Qué es (y qué no es) un análisis de WebTrustScan

WebTrustScan es una **auditoría externa de configuración de seguridad**: observa lo que una web expone a cualquier visitante y lo compara con buenas prácticas publicadas.

**No es** una prueba de intrusión, un escáner de vulnerabilidades, una auditoría de código ni una certificación. Una puntuación alta significa «buena configuración en los controles comprobados», no «ausencia de vulnerabilidades». Este límite aparece en la interfaz, en cada informe y debe mantenerse en cualquier material comercial.

## 2. Niveles de comprobación

| Nivel | Descripción | Autorización | Estado |
|---|---|---|---|
| **Pasivo** | Se deduce de la respuesta que recibiría cualquier navegador a una petición `GET` normal. | No requiere (equivale a visitar la web) | Implementado |
| **Activo no intrusivo** | Una petición adicional, inocua y formulada a propósito: `GET` con cabecera `Origin`, `GET` a `http://`, `GET` a `/.well-known/security.txt`, un saludo TLS 1.0–1.1 sin datos. | No requiere; volumen mínimo y sin efectos | Implementado |
| **Profundo** | Rutas sensibles conocidas (lista cerrada), métodos HTTP, rastreo limitado del propio dominio. | **Verificación de propiedad del dominio** | Diseñado, no implementado (Pro) |
| **Autenticado** | Controles tras el inicio de sesión (cookies reales de sesión, CSRF, control de acceso). | Propiedad + credenciales de prueba | Fuera de alcance por ahora |
| **Con acceso al código** | SAST, dependencias, secretos. | Acceso al repositorio | Fuera de alcance (otro producto) |

### Presupuesto de un análisis (nivel gratuito)

Como máximo **5 peticiones HTTP al sitio** (verificado por test) y un saludo TLS:

1. `GET` de la URL (hasta 5 redirecciones, 512 KB de cuerpo).
2. `GET http://host/` — redirección a HTTPS.
3. `GET` de la URL con `Origin: https://cors-probe.webtrustscan.invalid` — política CORS.
4. `GET /.well-known/security.txt`.
5. Saludo TLS limitado a 1.0–1.1 (sin petición HTTP).

Más consultas DNS (MX, TXT, CAA) al resolvedor, que no tocan el sitio. Tiempos: 8 s por petición principal, 6 s por sonda, 20 s en total.

### Lo que nunca se hace

Explotación, envío de *payloads*, fuerza bruta, enumeración de usuarios o subdominios, *fuzzing*, escaneo de puertos, peticiones con métodos que modifiquen estado, ni ninguna acción que dependa de que el sitio sea vulnerable para funcionar.

## 3. Referencias y versiones vigentes

Versiones comprobadas el 15 de noviembre de 2026.

| Referencia | Versión usada | Nota |
|---|---|---|
| OWASP Application Security Verification Standard | **5.0.0** (30 de mayo de 2025) | Última estable ([repositorio](https://github.com/OWASP/ASVS)). Se usa el capítulo V3 «Web Frontend Security» para cabeceras, cookies y CORS. |
| OWASP Web Security Testing Guide | **4.2** | Última estable; la 5.0 sigue en desarrollo ([repositorio](https://github.com/OWASP/wstg)). Los identificadores `WSTG-…` son los de 4.2. |
| OWASP Secure Headers Project | Vigente (documento vivo) | Lista de cabeceras recomendadas y obsoletas. |
| MDN Web Security / HTTP Observatory | Vigente | Semántica de cabeceras y comportamiento real de navegadores. |
| RFC 6797 | HSTS | Incluida la regla de «primera cabecera» (§8.1). |
| RFC 8996 | Retirada de TLS 1.0 y 1.1 | |
| RFC 5280, RFC 9525 | Certificados X.509 y verificación de identidad del servicio | |
| RFC 9110 | Semántica HTTP | |
| RFC 6265bis | Cookies (SameSite, prefijos `__Host-` / `__Secure-`) | Borrador IETF; es lo que implementan los navegadores. |
| RFC 7034 | X-Frame-Options | Sustituido en la práctica por `frame-ancestors` (CSP Level 3). |
| W3C CSP Level 3, Mixed Content, SRI, Referrer Policy, Permissions Policy | Vigentes | |
| WHATWG Fetch | CORS y `X-Content-Type-Options` | |
| RFC 9116 | security.txt | |
| RFC 7208, RFC 7489, RFC 8659 | SPF, DMARC, CAA | |

Los identificadores exactos de requisitos ASVS deben revisarse contra el texto de la 5.0.0 antes de citarlos en un informe comercial: en el catálogo se referencia el capítulo, no el número de requisito, precisamente para no citar de memoria.

## 4. Correspondencia control → referencia → nivel

| Control | Referencia principal | Nivel |
|---|---|---|
| HTTPS disponible, versión TLS | WSTG-CRYP-01, RFC 8996 | Pasivo |
| Certificado válido | WSTG-CRYP-01, RFC 5280, RFC 9525 | Pasivo |
| Protocolos TLS obsoletos | RFC 8996 | Activo |
| Redirección HTTP → HTTPS | RFC 6797 §7 | Activo |
| HSTS | RFC 6797, OWASP Secure Headers | Pasivo |
| CSP | CSP Level 3, WSTG-CONF-12, ASVS V3 | Pasivo |
| Clickjacking | CSP3 `frame-ancestors`, RFC 7034, WSTG-CLNT-09 | Pasivo |
| X-Content-Type-Options | WHATWG Fetch, ASVS V3 | Pasivo |
| Referrer-Policy, Permissions-Policy | Especificaciones W3C | Pasivo |
| Cookies | RFC 6265bis, WSTG-SESS-02, ASVS V3 | Pasivo |
| CORS | WHATWG Fetch, WSTG-CLNT-07 | Activo |
| Contenido mixto, formularios | W3C Mixed Content, WSTG-CRYP-03 | Pasivo |
| SRI | W3C SRI | Pasivo |
| Versiones expuestas | WSTG-INFO-02 | Pasivo |
| security.txt | RFC 9116 | Activo |
| SPF, DMARC, CAA | RFC 7208, 7489, 8659 | Pasivo (DNS) |

## 5. Reglas de evidencia

1. **Todo hallazgo lleva evidencia**: la cabecera tal y como se recibió, el campo del certificado, el recurso concreto. Si no hay evidencia, no hay hallazgo.
2. **Se informa de configuración, no de explotabilidad.** Una política CORS permisiva se describe como tal y se explica de qué depende su impacto; no se declara «vulnerable».
3. **Un *banner* no es una vulnerabilidad.** Revelar una versión se trata como exposición de información de severidad baja. No se correlaciona con CVE (ver `CHECK_CATALOG.md`).
4. **La confianza se declara.** Las conclusiones heurísticas (p. ej. «esta cookie parece de sesión») llevan confianza media y penalizan menos.
5. **Los valores sensibles no se guardan.** Los valores de las cookies se descartan al parsear y no aparecen en ningún informe (verificado por test).
6. **El análisis se describe a sí mismo.** Cada informe indica qué respondió el sitio, si había un intermediario, qué no se pudo comprobar y por qué.

## 6. Distinción entre problema del sitio y problema del análisis

| Situación | Tratamiento |
|---|---|
| El dominio no existe, no responde o agota el tiempo en la petición principal | Error explícito al usuario. No hay informe ni puntuación. |
| El destino no es analizable (IP interna, puerto no permitido) | Error 400. |
| WAF/CDN bloquea, 429 o 5xx | Informe parcial: controles de respuesta `NOT_TESTED`, normalmente sin puntuación. |
| Una sonda secundaria falla o agota el tiempo | Ese control queda `NOT_TESTED`; el resto del informe se entrega. |
| El resolvedor DNS falla | Controles DNS en `ERROR`; el informe web no se ve afectado. |
| Un check lanza una excepción interna | Ese control queda `ERROR`, se registra en el log y no penaliza. |

## 7. Seguridad del propio analizador

Todas las conexiones salientes —peticiones HTTP, HTTPS y la sonda TLS— pasan por `lib/audit/safeRequest.ts`, que aplica las protecciones de las auditorías 1 y 2: lista de rangos bloqueados, resolución DNS guardada, verificación de la IP real del socket, revalidación en cada redirección, puertos 80/443 y tiempos máximos. Ningún módulo de análisis abre conexiones por su cuenta: reciben un contexto ya recogido.

El modo de inspección TLS (`tlsMode: "inspect"`) desactiva únicamente la validación del certificado para poder informar de él; no relaja ninguna comprobación de destino (verificado por test con IP internas, metadata cloud e IPv6).
