# CALIBRATION_REPORT — Calibración con dos análisis reales

**Fecha:** 15 de noviembre de 2026 · **Casos:** `www.amazon.es` y `termlifepicks.com`.

Los informes originales no se adjuntaron, así que cada análisis se reprodujo con el motor (una vez antes y una vez después de los cambios; TermLifePicks, además, dos veces desde el panel para probar el historial). No se ha modificado nada en ninguno de los dos sitios. Cada corrección tiene su test en `tests/engine/calibration.test.ts`.

## Resultado

| Sitio | Motor 1.x | Engine 2.0 antes | Engine 2.0 calibrado | Correo y DNS |
|---|---|---|---|---|
| www.amazon.es | 78 | 77 | **85 (B)** | 85 → **100 (A)** |
| termlifepicks.com | 77 | 60 | **61 (C)** | 57 → **59 (D)** |

## Amazon.es

| Pregunta | Conclusión | Cambio |
|---|---|---|
| ¿Se interpreta bien la CSP? | **Sí.** La política aplicada es `upgrade-insecure-requests; report-uri …`: no contiene `script-src` ni `default-src`. La política con `default-src` está solo en Report-Only. | La descripción ahora nombra las directivas declaradas y menciona la política Report-Only. |
| ¿Las cookies son realmente de sesión? | **No se podía afirmar, y además había un error.** Amazon envía, junto a las cookies reales, cabeceras que *borran* cookies antiguas de otro dominio (`session-id=-; expires=2014`). El motor se quedaba con la última por nombre y veía una «cookie de sesión sin Secure» que no existe. La detección dependía solo del nombre. | Las cookies se identifican por nombre + dominio + ruta; los borrados se ignoran; para considerar una cookie «de sesión» hace falta un nombre de framework conocido, o un nombre sugerente **y** un valor con aspecto de identificador. |
| ¿Severidad y confianza adecuadas? | Estaban infladas. | Cookies: confianza media (nombre conocido) o baja (indicio), visible en cada hallazgo. Resultado real en Amazon: solo `i18n-prefs` y `lc-acbes` sin `Secure`, severidad baja; HttpOnly no aplica. |
| ¿Acepta TLS 1.1 `www.amazon.es`? | **Sí, confirmado de forma independiente** con OpenSSL (`openssl s_client -tls1_1`): completa el saludo con TLS 1.1 y también con TLS 1.0. | Severidad bajada a **baja** (los navegadores actuales no negocian esas versiones); la evidencia incluye el comando para reproducirlo. |
| ¿CAA bien descrito y puntuado? | No: se trataba como fallo, cuando CAA es opcional y la mayoría de dominios no lo publica. | Ausencia de CAA = **informativo, sin peso**. |

También se corrigió un falso positivo de SRI: `m.media-amazon.com` es el CDN propio de Amazon y se contaba como tercero (10 de 10 recursos «sin integrity»).

## TermLifePicks

| Pregunta | Conclusión | Cambio |
|---|---|---|
| ¿61 es proporcional? | **Sí.** El transporte es correcto salvo HSTS, pero de las protecciones del navegador solo está Permissions-Policy (1 de 4). | — |
| ¿CSP ausente: alta o media? | **Media.** Es una defensa en profundidad; su ausencia no es una vulnerabilidad. Conserva un peso alto en la nota (10). | Severidad a media y texto que lo dice expresamente. |
| ¿Penalizaciones duplicadas? | **No.** CSP (scripts), clickjacking (marcos), HSTS y nosniff cubren ataques distintos. Una sola cabecera CSP con `frame-ancestors` resolvería dos de ellos, y así se explica. | — |
| ¿SRI distingue estáticos de dinámicos? | **No lo hacía.** Penalizaba Google Tag Manager y AdSense, que cambian su código por diseño y no admiten SRI. | Clasificación en propio / versión fija / dinámico. Solo puntúan los de versión fija; los dinámicos se listan como informativos con su URL. |
| ¿DMARC bien explicado? | Era incompleto. El registro es `v=DMARC1; p=none;` **sin `rua`**: ni protege ni envía informes. | Dos casos distintos: `p=none` con informes (crédito 0,4, «primera fase normal») y sin informes (0,25, «no protege ni informa»). |
| ¿Se diferencia web de DNS/correo? | Sí en datos; mejorable en pantalla. | Informe aparte, renombrado «Correo y DNS», con un texto que explica que no altera la nota web. |
| ¿Nota de DNS engañosa con un solo control? | **Sí.** | Con menos de 2 controles evaluados no se publica nota de correo (6 en el informe web). En categorías con menos de 3 controles se muestra «1 de 1 correcto» en lugar de un porcentaje. |

## Otros cambios derivados

- Las entidades HTML de los atributos se decodifican (`&#038;` aparecía en las URL de evidencia).
- La redirección HTTP → HTTPS pasa a severidad media, en línea con HSTS.
- El informe muestra cuántos controles se han evaluado, cuántos no aplican y cuántos no se pudieron comprobar.

## Límites de esta calibración

Dos sitios no son una muestra. Las listas de servicios «dinámicos» y la detección de CDN propio por nombre de marca son heurísticas que fallarán en algún caso; por eso SRI lleva confianza media. Hace falta repetir el ejercicio con 20–30 dominios autorizados.
