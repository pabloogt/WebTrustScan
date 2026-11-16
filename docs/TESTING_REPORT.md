# TESTING_REPORT — Pruebas y verificación

**Actualizado:** 16 de noviembre de 2026 · **Entorno:** Windows 11, Node 24.14.1, OpenSSL 3.2.4 · **Rama:** `engine-2.0-revision` (cambios sin commitear).

Este documento separa cuatro niveles que no son lo mismo:

| Nivel | Significado |
|---|---|
| **Prueba automática** | La ejecuta `npm test`. Simula el entorno (servidores locales, PostgreSQL embebido, un doble de Supabase Auth). |
| **Comprobado a mano** | Hecho en este equipo con la aplicación real en marcha. |
| **Sin verificar** | Implementado, pero no ejecutado contra el servicio real. |
| **No implementado** | No existe. |

## 1. Suite automática

`npx vitest run`: **539 pruebas, 539 pasan, 0 fallan**, en 23 ficheros.

| Antes de esta fase | Ahora |
|---|---|
| 492 pruebas en 21 ficheros | 539 pruebas en 23 ficheros |

Se retiraron las 107 pruebas del sistema de cuentas anterior (autenticación propia sobre PGlite), porque el código que probaban ya no existe, y se añadieron 154 nuevas. Las 385 restantes no se han tocado, salvo las dos excepciones indicadas abajo.

| Fichero | Pruebas | Qué cubre |
|---|---|---|
| `analyze`, `checks`, `clientIp`, `csp`, `ipGuard`, `normalizeUrl`, `rateLimit`, `route`, `safeRequest`, `ssrfRebinding` | 222 | Suite histórica de las auditorías 1 y 2 |
| `engine/scoring`, `parsers`, `transport`, `calibration`, `revision` | 131 | Motor: fórmula, parsers, red, calibración y revisión técnica |
| `lab/lab` | 27 | 31 escenarios, motor 1.x frente a 2.0 |
| `report/pdf` | 5 | Generación del PDF |
| `db/smoke`, `db/rls`, `db/quota` | 42 | Migraciones, RLS, permisos y consumo sobre PostgreSQL |
| `accounts/flows` | 35 | Alta, confirmación, acceso, recuperación, cambios, borrado, exportación, aislamiento |
| `accounts/analyze` | 20 | Cuotas por la ruta real del analizador |
| `accounts/limits` | 57 | Límites, HMAC, Upstash, configuración y cuentas desactivadas |

Otras comprobaciones: `tsc --noEmit` sin errores · `eslint` sin errores · `next build` correcto (18 rutas) · `npm audit` 0 vulnerabilidades.

**Pruebas históricas modificadas (2 de 222), y por qué:**

- `route.test.ts`, dos casos con `VERCEL=1`: ahora, en un entorno tipo Vercel sin Upstash, el analizador responde 503 en lugar de limitar en memoria. Esos casos prueban la identificación de la IP, así que declaran de forma explícita `RATE_LIMIT_ALLOW_MEMORY=true`. El comportamiento nuevo tiene sus propias pruebas.
- `csp.test.ts`: `proxy` pasa a ser asíncrono (renueva la sesión); las pruebas lo esperan con `await`. No cambia lo que comprueban.

**Fallos conocidos:** ninguno en esta ejecución. Un test histórico de límite de peticiones falló una vez hace dos fases y no se ha vuelto a reproducir; no se ha investigado.

## 2. Qué simulan las pruebas nuevas (y qué no)

| Área | Cómo se prueba | Qué NO prueba |
|---|---|---|
| Base de datos, RLS, cuota | Las migraciones reales de `supabase/migrations/` aplicadas a PostgreSQL embebido (PGlite), con los roles `anon`, `authenticated` y `service_role` y el JWT como los fija Supabase | La API de Supabase; la concurrencia entre varias conexiones |
| Flujos de cuenta | Las rutas reales de la aplicación; datos y cuota contra ese PostgreSQL; **la autenticación es un doble** que imita el comportamiento documentado de Supabase Auth | Supabase Auth: envío de correos, formato real de los enlaces, cookies, códigos de error reales |
| Cuotas del analizador | La ruta real `/api/analyze`; el motor se sustituye por un doble para no salir a la red | — |
| Upstash | El cliente oficial con `fetch` simulado (respuesta correcta y caída) | Una base Redis real |

Las 42 pruebas de base de datos son la parte más sólida: ejecutan el SQL que se desplegará. Las de flujos demuestran que **nuestra** lógica es correcta (respuestas que no revelan cuentas, límites, redirecciones, aislamiento), no que la integración con Supabase funcione.

## 3. Comprobado a mano en este equipo

| Comprobación | Resultado |
|---|---|
| Servidor de producción local (`next build` + `next start`) sin ninguna variable | `/acceso`, `/panel`, `/cuenta/nueva-contrasena` y las rutas de cuentas → **404**. La portada no enlaza a la cuenta. |
| Mismo servidor, analizador sin Upstash | **503** «El servicio no está disponible en este momento» (antes: funcionaba con límites por instancia). |
| PDF de Amazon.es y TermLifePicks | Regenerados desde los informes guardados. **Contenido:** puntuaciones, cobertura, número de controles y títulos de hallazgos coinciden con el JSON. **Diseño:** las 10 páginas revisadas como imagen tras la última corrección; sin títulos huérfanos, etiquetas de evidencia junto a su valor, tablas, viñetas y caracteres correctos. |
| Generación del PDF bajo la CSP de producción | Sin errores ni infracciones de CSP. |
| **Descarga real del PDF desde el navegador** | **No verificada por mí.** Pulsé «Descargar PDF» en el navegador integrado de la herramienta y no apareció ningún fichero nuevo en disco (ese navegador no parece guardar descargas). En la carpeta de Descargas hay dos PDF descargados antes por el propietario del proyecto; el más reciente es un PDF válido de 5 páginas. Falta una comprobación explícita en Chrome, Firefox y Safari. |
| Los informes no muestran datos de otro usuario | Prueba automática: con el identificador de un informe ajeno, 404. No comprobado a mano con dos cuentas reales. |
| Versiones TLS de `www.amazon.es` con OpenSSL | Fase anterior: acepta 1.0, 1.1, 1.2 y 1.3; coincide con el motor. |
| Duración de un análisis | 0,9 s (Amazon) y 1,2 s (TermLifePicks) desde este equipo. No medido en Vercel. `maxDuration` sigue en 30 s, sin cambios. |

## 4. Sin verificar

| Qué | Por qué |
|---|---|
| **Todo Supabase** (Auth, API, cookies, correos, migraciones con la CLI) | Docker Desktop no está instalado en este equipo: no se pudo arrancar Supabase local. No hay proyecto en la nube. |
| Tipos generados por Supabase | Requieren la base en marcha. Los actuales están escritos a mano. |
| Upstash real | Sin base ni credenciales. |
| Resend | Sin cuenta ni dominio verificado. |
| Vercel: variables, región, duración, cabeceras de IP, cookies en HTTPS | Sin despliegue. |
| Interfaz de cuentas en el navegador (acceso, panel, configuración, plan) | Compila y pasa lint y tipos, pero **no se ha abierto con datos reales**: necesita Supabase en marcha. |
| Concurrencia real de la cuota | PostgreSQL embebido usa una sola conexión. |

## 5. Regresión del analizador

| Comprobación | Resultado |
|---|---|
| Suite histórica | 222 / 222 (con las dos adaptaciones descritas) |
| Laboratorio | 27 / 27; las notas de los 31 escenarios no han cambiado |
| Protecciones SSRF, *rebinding*, tamaños y tiempos | Sin cambios en `lib/audit/`; sus pruebas pasan |
| Los planes no alteran el motor | El motor recibe solo la URL validada; un usuario Pro obtiene los mismos rechazos por destino interno |
| Puntuaciones | Ningún peso ni criterio modificado en esta fase |

**Cambio de comportamiento a tener presente antes de desplegar:** el analizador público pasa a tener un límite de 2 análisis al día por IP sin cuenta, y en producción **deja de funcionar si no están configurados Upstash e `IP_HASH_SECRET`**.

## 6. Laboratorio: motor 1.x frente a Engine 2.0

`tests/lab/results.json`, regenerado en esta revisión.

| # | Escenario | Motor 1.x | Engine 2.0 | Nota | Cobertura |
|---|---|---|---|---|---|
| s01 | Web correctamente configurada | 100 | 100 | A | 100 % |
| s02 | HTTPS con cabeceras deficientes | 39 | 58 | D | 100 % |
| s03 | Certificado caducado | error | 30 (tope) | F | 100 % |
| s03b | Certificado de otro dominio | error | 30 (tope) | F | 100 % |
| s03c | Certificado autofirmado | error | 30 (tope) | F | 100 % |
| s04 | CSP con `unsafe-inline` y comodín | 93 | 93 | A | 100 % |
| s04b | CSP solo en Report-Only | 88 | 83 | B | 100 % |
| s04c | CSP que solo declara `frame-ancestors` | 93 | 90 | A | 100 % |
| s04d | CSP en `<meta>` | 75 | 92 | A | 100 % |
| s05 | HSTS con `max-age=0` | 89 | 89 | B | 100 % |
| s05b | HSTS de 1 día | 94 | 95 | A | 100 % |
| s05c | Cabeceras duplicadas (CDN + origen) | 83 | 100 | A | 100 % |
| s06 | Cookies de sesión mal configuradas | 100 | 89 | B | 100 % |
| s07 | CORS con credenciales para cualquier origen | 100 | 89 (tope) | B | 100 % |
| s07b | CORS `*` sin credenciales | 100 | 100 | A | 100 % |
| s08 | Web estática sin cookies ni formularios | 100 | 100 | A | 100 % |
| s09 | API JSON con 401 | 61 | 100 | A | 100 % |
| s09b | API JSON con 403 sin nosniff | 39 | 78 | B | 100 % |
| s10 | CDN/WAF bloquea al analizador | 39 | sin puntuación | — | 34 % |
| s10b | Sitio normal servido por CDN | 100 | 100 | A | 100 % |
| s11 | Respuesta 429 | 39 | sin puntuación | — | 34 % |
| s12 | Redirecciones múltiples | 100 | 100 | A | 100 % |
| s14 | `frame-ancestors` sin X-Frame-Options | 100 | 100 | A | 100 % |
| s15 | Error temporal 503 | 39 | sin puntuación | — | 34 % |
| s15b | `http://` no responde | 94 | 100 | A | 92 % |
| s16 | Puerto HTTP cerrado | 94 | 100 | A | 100 % |
| s17 | Web solo HTTP | 55 | 35 (tope) | F | 100 % |
| s17b | `https://` cerrado, `http://` disponible | error | 35 (tope) | F | 100 % |
| s18 | Contenido mixto y formulario inseguro | 100 | 86 | B | 100 % |
| s19 | Versiones de software expuestas | 100 | 99 | A | 100 % |
| s20 | Servidor que acepta TLS 1.0/1.1 | 100 | 96 | A | 100 % |

## 7. Cómo repetirlo

```bash
npm ci
npm test
npm run typecheck
npm run lint
npm run build
```

Solo la base de datos: `npm run test:db`. Solo cuentas: `npm run test:accounts`.

Tabla del laboratorio (Git Bash): `LAB_REPORT=1 npx vitest run tests/lab`.
