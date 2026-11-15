# TESTING_REPORT — Laboratorio y verificación

**Fecha:** 15 de noviembre de 2026 · **Entorno:** Windows 11, Node 24.14.1, OpenSSL 3.2.4.

## 1. Qué se ha ejecutado y dónde

| Verificación | Tipo | Resultado |
|---|---|---|
| Suite histórica (10 ficheros) | Ejecutada localmente | **222 / 222** — sin modificar ningún test existente |
| Suite nueva del Engine 2.0 (4 ficheros) | Ejecutada localmente | **102 / 102** |
| **Total `vitest run`** | Ejecutada localmente | **324 / 324** en ~5 s |
| `tsc --noEmit` | Ejecutada localmente | Sin errores |
| `eslint` | Ejecutada localmente | Sin errores |
| `next build` (Next.js 16.4.6, Turbopack) | Ejecutada localmente | Compila; rutas `/`, `/_not-found`, `/api/analyze` dinámicas |
| `npm audit` | Ejecutada localmente | 0 vulnerabilidades |
| Interfaz sobre el build de producción (`next start`) | Ejecutada localmente en navegador | Informe renderizado con la CSP de nonces activa, sin errores de consola ni infracciones de CSP. Datos: informe generado por el laboratorio (respuesta de la API simulada). |
| Análisis de una web real de Internet | **No ejecutado** | Decisión deliberada: no se analizan sitios de terceros sin autorización. Pendiente de hacer con dominios propios. |
| Vercel: cabeceras `x-vercel-forwarded-for`, límites de duración, DNS y TLS 1.0 en su runtime | **No ejecutado** | Sin acceso a la infraestructura. |
| Upstash real | **No ejecutado** | Sin credenciales; no se ha contratado nada. |
| Exportación a PDF | Parcial | El flujo (vista técnica desplegada + `window.print()`) y la hoja de estilos de impresión están implementados; **no se ha revisado un PDF generado**. |

Desglose de tests nuevos: `engine/scoring` 26 · `engine/parsers` 33 · `engine/transport` 16 · `lab/lab` 27.

## 2. El laboratorio

`tests/lab/harness.ts` levanta, por escenario, un sitio simulado en `127.0.0.1`:

- **Servidor HTTPS real** con una CA propia de pruebas y cuatro certificados (`tests/lab/certs/`): válido, caducado (2022–2023), de otro dominio y autofirmado.
- **Servidor HTTP** configurable: redirige a HTTPS, sirve sin redirigir, puerto cerrado o conexión colgada.
- **DNS simulado**: `*.lab.test` resuelve a 127.0.0.1 mediante el `dnsLookup` inyectable de la capa segura; las zonas MX/TXT/CAA se simulan con un `DnsClient` inyectable, incluido un resolvedor que no responde.
- **Ambos motores** se ejecutan contra el mismo sitio: el 1.x congelado (`lib/audit/analyze.ts`) y el Engine 2.0.

Las opciones de prueba (`addressPolicy`, `allowedPorts: null`, `tlsCa`, `dnsLookup`) ya existían o siguen el mismo patrón que en las auditorías anteriores: solo relajan la política dentro de los tests y nunca se leen de variables de entorno ni de la petición.

Las claves privadas de `tests/lab/certs/` son de prueba, no protegen nada y no deben reutilizarse.

## 3. Resultados: motor 1.x frente a Engine 2.0

Generado con `LAB_REPORT=1 npx vitest run tests/lab` → `tests/lab/results.json`.

| # | Escenario | Motor 1.x | Engine 2.0 | Nota | Cobertura | Hallazgos abiertos (2.0) |
|---|---|---|---|---|---|---|
| s01 | Web correctamente configurada | 100 | 100 | A | 100 % | — |
| s02 | HTTPS con cabeceras deficientes | 39 | 58 | D | 100 % | HSTS, CSP, clickjacking, nosniff, Permissions-Policy |
| s03 | Certificado caducado (resto perfecto) | error `TLS_ERROR` | 30 (tope) | F | 100 % | certificado |
| s03b | Certificado de otro dominio | error `TLS_ERROR` | 30 (tope) | F | 100 % | certificado |
| s03c | Certificado autofirmado | error `TLS_ERROR` | 30 (tope) | F | 100 % | certificado |
| s04 | CSP con `unsafe-inline` y comodín | 93 | 93 | A | 100 % | CSP (aviso) |
| s04b | CSP solo en Report-Only | 88 | 83 | B | 100 % | CSP (aviso), clickjacking (aviso) |
| s04c | CSP que solo declara `frame-ancestors` | 93 | 90 | A | 100 % | CSP (aviso) |
| s04d | CSP en `<meta>` (hosting estático) | 75 | 92 | A | 100 % | clickjacking |
| s05 | HSTS con `max-age=0` | 89 | 89 | B | 100 % | HSTS |
| s05b | HSTS de 1 día | 94 | 95 | A | 100 % | HSTS (aviso) |
| s05c | Cabeceras duplicadas (CDN + origen) | 83 | 100 | A | 100 % | — |
| s06 | Cookies de sesión mal configuradas | 100 | 89 | B | 100 % | Secure, HttpOnly, SameSite (aviso) |
| s07 | CORS: refleja el origen con credenciales | 100 | 89 (tope) | B | 100 % | CORS |
| s07b | CORS: `*` sin credenciales | 100 | 100 | A | 100 % | — |
| s08 | Web estática sin cookies ni formularios | 100 | 100 | A | 100 % | — |
| s09 | API JSON con 401 | 61 | 100 | A | 100 % | — |
| s09b | API JSON con 403 sin nosniff | 39 | 78 | B | 100 % | HSTS, nosniff |
| s10 | CDN/WAF bloquea al analizador | 39 | sin puntuación | — | 34 % | — |
| s10b | Sitio normal servido por CDN | 100 | 100 | A | 100 % | — |
| s11 | Respuesta 429 | 39 | sin puntuación | — | 34 % | — |
| s12 | Redirecciones múltiples (3 saltos) | 100 | 100 | A | 100 % | — |
| s14 | `frame-ancestors` sin X-Frame-Options | 100 | 100 | A | 100 % | — |
| s15 | Error temporal 503 | 39 | sin puntuación | — | 34 % | — |
| s15b | `http://` no responde (timeout) | 94 | 100 | A | 92 % | — (redirección no comprobada) |
| s16 | Puerto HTTP cerrado | 94 | 100 | A | 100 % | — |
| s17 | Web solo HTTP | 55 | 35 (tope) | F | 100 % | HTTPS |
| s17b | `https://` cerrado, `http://` disponible | error `UNREACHABLE` | 35 (tope) | F | 100 % | HTTPS |
| s18 | Contenido mixto y formulario inseguro | 100 | 86 | B | 100 % | contenido mixto, formularios, SRI (aviso) |
| s19 | Versiones de software expuestas | 100 | 99 | A | 100 % | *banner* |
| s20 | Servidor que acepta TLS 1.0/1.1 | 100 | 96 | A | 100 % | TLS antiguo |

Además: s13 (dominio inexistente → error claro, sin informe), s13b (resolvedor DNS caído → controles DNS en `ERROR`, informe web intacto) y s13c (DNS/correo se puntúa aparte: un `+all` en SPF deja el informe de correo en F y el web en 100).

### Cobertura de los 15 escenarios pedidos

| Pedido | Escenario(s) |
|---|---|
| 1. Web correctamente configurada | s01 |
| 2. HTTPS con cabeceras deficientes | s02 |
| 3. Certificado expirado | s03, s03b, s03c |
| 4. CSP incorrecta | s04, s04b, s04c, s04d |
| 5. HSTS inseguro | s05, s05b |
| 6. Cookies mal configuradas | s06 |
| 7. CORS permisivo | s07, s07b |
| 8. Web sin cookies ni formularios | s08 |
| 9. API 401 y 403 | s09, s09b |
| 10. CDN | s10, s10b, s05c |
| 11. Respuesta 429 | s11 |
| 12. Redirecciones | s12 |
| 13. Problemas DNS | s13, s13b, s13c |
| 14. CSP equivalente a X-Frame-Options | s14 |
| 15. Errores temporales | s15, s15b |

## 4. Regresión de seguridad (superficies nuevas)

`tests/engine/transport.test.ts` comprueba que lo añadido a la capa de comunicación no abre vías nuevas:

- El modo `inspect` de TLS sigue bloqueando `127.0.0.1`, `10.0.0.5`, `169.254.169.254`, `[::1]` y `[::ffff:127.0.0.1]`.
- La sonda TLS valida esquema, puerto e IP resuelta, y corta un dominio que resuelve a una IP interna.
- Una redirección hacia la IP de metadatos aborta el análisis completo (`BLOCKED_TARGET`).
- El motor nuevo rechaza `localhost`, IP privadas y `file://` con la configuración por defecto.
- El cuerpo se limita en bytes y una bomba de compresión (64 MB) se descarta sin agotar memoria.
- El valor de las cookies no aparece en el informe.
- Un análisis no hace más de 5 peticiones al sitio.
- El tiempo total se respeta; si se agota durante las sondas, se entrega el informe con lo comprobado.

Los 32 tests de DNS rebinding y los 30 de rate limiting de la segunda auditoría siguen pasando sin cambios; el núcleo que ejercitan (`createGuardedLookup`, comprobación del socket) es el mismo que usan ahora todas las conexiones.

## 5. Rendimiento (laboratorio)

Con latencia de red nula, un análisis completo tarda del orden de decenas de milisegundos; los 27 escenarios del laboratorio, con sus dos motores y los casos de *timeout*, suman ~4 s. No es representativo de producción: el tiempo real lo dominará la latencia del sitio analizado. Las cuatro sondas secundarias y el DNS se lanzan en paralelo tras la petición principal, así que el coste añadido respecto al motor 1.x (que hacía dos peticiones en serie) debería ser pequeño. **Pendiente de medir en Vercel.**

## 6. Limitaciones de estas pruebas

- Todo el tráfico es local: no se ha validado el comportamiento frente a servidores, CDN y WAF reales. Las firmas de bloqueo (Cloudflare, Akamai, Imperva, Sucuri, AWS WAF) proceden de documentación y experiencia, no de capturas hechas en esta sesión.
- La sonda de TLS 1.0–1.1 funciona con el OpenSSL de este Node. En otro runtime puede no estar disponible; en ese caso el control queda `NOT_TESTED` (código previsto, no verificado en Vercel).
- Las consultas DNS reales (`node:dns` → `resolveCaa`, `resolveTxt`, `resolveMx`) no se han ejecutado contra Internet; solo contra la zona simulada.
- El analizador de HTML es un escáner de etiquetas tolerante, probado con casos representativos, no con un corpus amplio.
