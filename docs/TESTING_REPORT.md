# TESTING_REPORT — Pruebas y verificación

**Actualizado:** 15 de noviembre de 2026 (revisión técnica) · **Entorno:** Windows 11, Node 24.14.1, OpenSSL 3.2.4 · **Rama:** `engine-2.0-revision`.

Este documento separa tres cosas que no son lo mismo: lo que cubre una **prueba automática**, lo que se ha **comprobado a mano** en esta máquina y lo que **no se ha comprobado**.

## 1. Resultado de la suite automática

`npx vitest run`: **492 pruebas, 492 pasan, 0 fallan**, en 21 ficheros (~10 s).

| Fichero | Pruebas | Qué cubre |
|---|---|---|
| `analyze`, `checks`, `clientIp`, `csp`, `ipGuard`, `normalizeUrl`, `rateLimit`, `route`, `safeRequest`, `ssrfRebinding` | 222 | Suite histórica de las auditorías 1 y 2, **sin modificar** |
| `engine/scoring` | 26 | Fórmula, cobertura, topes, confianza |
| `engine/parsers` | 33 | CSP, cookies, HTML |
| `engine/transport` | 16 | Regresión de seguridad de la capa de red |
| `engine/calibration` | 28 | Casos derivados de Amazon y TermLifePicks |
| `engine/revision` | 28 | Esta revisión: TLS por versión, SPF/DMARC, HSTS, CSP, heurísticas, transparencia |
| `lab/lab` | 27 | 31 escenarios, motor 1.x frente a 2.0 |
| `report/pdf` | 5 | Generación del PDF |
| `pro/auth` | 22 | Contraseñas, sesiones, cookies, CSRF, límite de intentos |
| `pro/domains-audits` | 26 | Dominios, verificación, historial, comparación |
| `pro/isolation` | 15 | Aislamiento entre organizaciones |
| `pro/disabled` | 44 | Cuentas desactivadas por defecto |

Otras comprobaciones ejecutadas: `tsc --noEmit` sin errores · `eslint` sin errores · `next build` correcto (15 rutas) · `npm audit` 0 vulnerabilidades.

**Fallos conocidos:** ninguno en esta ejecución. En la fase anterior un test histórico de límite de peticiones («un token incorrecto se trata como fallo del almacén») falló una vez y no se ha vuelto a reproducir en ninguna de las ejecuciones posteriores; no se ha investigado la causa.

## 2. Pruebas de esta revisión

Todas se ejecutan contra servidores TLS y HTTP reales levantados en `127.0.0.1` por el laboratorio (`tests/lab/harness.ts`), con DNS simulado. Son automáticas y **simulan** los sitios; no sustituyen a las comprobaciones de §3.

| Requisito | Prueba |
|---|---|
| Aceptación y rechazo de cada versión TLS | Servidor moderno (1.0 y 1.1 rechazados con alerta, 1.2 y 1.3 aceptados); servidor que acepta las cuatro; servidor que acepta 1.1 pero no 1.0; servidor sin 1.3 |
| Versión negociada frente a versiones admitidas | La evidencia incluye la conexión normal y un saludo por versión; el control de versión negociada sigue correcto aunque se acepten versiones antiguas |
| Un error del cliente no es un rechazo | Puerto cerrado, dominio que no resuelve, servidor que no responde al saludo y servicio que no habla TLS dan «no comprobable»; con una versión antigua sin probar el control queda «no comprobado» |
| DMARC `p=none` y ausencia de `rua` | El texto no afirma que los mensajes se entreguen; menciona los filtros del receptor y la falta de destino para informes |
| SPF `~all` frente a `-all` | Se describen como softfail y fail, con textos distintos |
| HSTS sin `includeSubDomains` automático | La cabecera propuesta no lo lleva; se explica el impacto en subdominios; `preload` no se recomienda |
| CSP en Report-Only | Recomendación «Report-Only primero», terceros detectados nombrados, aviso de WordPress; se distingue política aplicada de política en pruebas |
| Puntuación ponderada, cobertura y confianza | Ejemplo «1 de 4 correctos = 9/100»; la puntuación se recalcula a partir de los hallazgos y coincide |
| Límites del informe de correo | El aviso existe y aparece en interfaz y PDF |
| Falsos positivos y negativos en cookies y SRI | Identificadores solo numéricos, prioridad de `Max-Age`, marca como palabra completa (`shopify` ≠ `shop`), tercero sin versión visible, 403 genérico |
| Cuentas desactivadas | Las 13 rutas responden 404 con y sin sesión, no consultan la base de datos, no crean cuentas; el analizador público responde |

## 3. Comprobaciones manuales realizadas en esta máquina

| Comprobación | Cómo | Resultado |
|---|---|---|
| Versiones TLS de `www.amazon.es` con una herramienta independiente | `openssl s_client` con `-tls1`, `-tls1_1`, `-tls1_2`, `-tls1_3` y sin opción | Acepta las cuatro; una conexión normal negocia TLS 1.3. Coincide con el motor. |
| Análisis real de `www.amazon.es` y `termlifepicks.com` | Una ejecución del motor por sitio tras las correcciones | 82 (B) y 61 (C). Informes guardados en `docs/informes/`. |
| PDF de ambos sitios | Generados a partir de esos informes; las 5 páginas de cada uno revisadas como imagen y por su texto extraído | Sin caracteres rotos; URL y evidencias completas; saltos de página corregidos (ver abajo). |
| PDF bajo la CSP de producción | `next build` + `next start`; informe mostrado en el navegador; pulsado «Descargar PDF» | Archivo válido de 14 640 bytes (`%PDF-1.7` … `%%EOF`), tipo `application/pdf`, **0 infracciones de CSP**. |
| Cuentas desactivadas en el servidor real | Mismo servidor, sin ninguna variable de entorno | `/acceso` y `/panel` → 404; registro, acceso, sesión, dominios y comparación → 404; la portada no enlaza al panel. |

Defectos encontrados al revisar los PDF y corregidos: una viñeta partida entre dos páginas a mitad de frase, una evidencia separada de su etiqueta, una entrada de la lista de controles partida, dos títulos de sección aislados al pie de página y los controles informativos sin sus URL de evidencia. Tras la última corrección (títulos aislados) la comprobación se hizo sobre el texto de cada página, no de nuevo como imagen.

Matices:

- En la prueba del PDF bajo CSP, la respuesta de `/api/analyze` se sustituyó por el informe guardado de TermLifePicks para no repetir el análisis, y **se impidió el guardado del fichero en disco**: se verificó el contenido generado, no el diálogo de descarga del navegador.
- No se me adjuntaron los dos PDF de referencia que mencionas; la comparación se hizo contra los generados en la fase anterior.

## 4. No comprobado

| Qué | Por qué |
|---|---|
| Comportamiento en Vercel (DNS, sondas TLS, duración, cabeceras de IP) | Sin despliegue. Las sondas TLS han pasado de una a cuatro por análisis; se lanzan en paralelo, pero su efecto en la duración real no está medido. |
| Sondas de TLS 1.0/1.1 en el runtime de Vercel | Si su OpenSSL no las permite, el control quedará «no comprobado» (previsto en código, no verificado allí). |
| Cuentas sobre PostgreSQL real | Solo se han ejecutado sobre PGlite. |
| Cookie de sesión `__Host-` y `Secure` en un dominio HTTPS | Requiere un despliegue. |
| Guardado real del PDF en disco desde el navegador y aspecto en distintos visores | No ejecutado. |
| Más sitios reales | Solo dos. Las heurísticas necesitan una muestra mayor de dominios autorizados. |
| Bloqueos reales de CDN/WAF | Las marcas de bloqueo proceden de documentación, no de capturas. |

## 5. Regresión

| Comprobación | Resultado |
|---|---|
| El analizador público sigue funcionando | Suite histórica intacta (222/222); ruta `/api/analyze` probada con las cuentas desactivadas; análisis reales completados |
| Las puntuaciones no cambian sin motivo | Los 31 escenarios del laboratorio dan **exactamente** las mismas notas que antes de la revisión. Único cambio real: Amazon 85 → 82, justificado en `SCORING_MODEL.md` §6 |
| Los PDF siguen generándose | 5 tests + generación real de dos informes |
| Las protecciones SSRF siguen activas en las vías nuevas | Las cuatro sondas TLS usan la misma validación de destino; tests de IP internas, puerto y *rebinding* |
| Presupuesto de peticiones | Máximo 5 peticiones HTTP por análisis (test). Saludos TLS: 4 (antes 1), sin datos de aplicación |

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

Tabla del laboratorio (Git Bash): `LAB_REPORT=1 npx vitest run tests/lab`.
