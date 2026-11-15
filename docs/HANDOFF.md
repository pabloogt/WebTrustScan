# HANDOFF — Cómo continuar

**Fecha:** 15 de noviembre de 2026 · **Rama:** `main` · **Estado del árbol:** todo el trabajo está **sin commitear** (ver §2).

## 1. Estado en una frase

El Engine 2.0 está implementado, conectado a `/api/analyze` y a la interfaz, y verificado en local con 324 tests, tipos, lint y build. **No se ha desplegado, no se ha probado contra webs reales y no se ha construido nada de Pro que necesite cuentas o base de datos.**

## 2. Git: lo primero que hay que hacer

El repositorio tiene en el árbol de trabajo, sin commit, tres rondas acumuladas: las correcciones de las auditorías 1 y 2 y este Engine 2.0. Un `git checkout .` o un `git clean` lo perdería todo.

No he hecho ningún commit porque no me lo has pedido. Recomendación: revisar y commitear cuanto antes, idealmente en una rama (`engine-2.0`) para poder desplegarla en Preview sin tocar producción.

Ficheros nuevos de esta fase:

```
lib/engine/                 Motor 2.0 (types, catalog, context, run, scoring, dnsClient, checks/, parse/)
components/report/          Informe (ReportView, ScorePanel, FindingCard, labels)
tests/engine/               Scoring, parsers, regresión de seguridad
tests/lab/                  Laboratorio + certificados de prueba + results.json
docs/                       Los nueve documentos
.github/workflows/ci.yml    CI
.claude/launch.json         Configuración de previsualización local
```

Ficheros existentes modificados en esta fase: `lib/audit/safeRequest.ts` (ampliado), `lib/audit/errors.ts` (campo `reason`), `lib/audit/{analyze,checks,score}.ts` (solo un comentario de cabecera), `app/api/analyze/route.ts` (usa `runAudit`), `app/page.tsx`, `app/globals.css`, `components/UrlForm.tsx`, `package.json` (script `test:lab`), `README.md`.

Sin usar desde ahora, pero **no borrados** (tienen cambios sin commitear de rondas anteriores): `components/ChecksList.tsx`, `components/ScoreOverview.tsx`, `types/audit.ts` (este último lo usa aún el motor 1.x). Se pueden eliminar los dos componentes después del commit.

## 3. Cómo verificar

```bash
npm ci
npm test
npm run typecheck
npm run lint
npm run build
```

Resultado esperado: 324 tests, sin errores de tipos ni de lint, build correcto.

Para probar a mano: `npm run dev` y analizar **un dominio tuyo**. El analizador rechaza `localhost` e IP privadas por diseño, así que no se puede apuntar a un servidor local desde la interfaz; para eso está el laboratorio (`npm run test:lab`).

## 4. Arquitectura del motor

```
runAudit(url)                                   lib/engine/run.ts
  ├─ safeFetch (petición principal, TLS en modo inspección, 512 KB)
  ├─ en paralelo: http://, sonda CORS, security.txt, sonda TLS 1.0–1.1, DNS
  ├─ clasifica la respuesta (ok / error / auth / 429 / 5xx / bloqueada)
  ├─ construye ScanContext                      lib/engine/context.ts
  ├─ ejecuta ALL_CHECKS → Finding[]             lib/engine/checks/*
  └─ scoreReport("web") y scoreReport("dns-email")   lib/engine/scoring.ts
```

Reglas que conviene no romper:

1. **Toda salida a red pasa por `lib/audit/safeRequest.ts`** (`safeFetch`, `safeTlsProbe`). Los checks no hacen peticiones: leen el `ScanContext`.
2. **Los checks no conocen los pesos.** Devuelven un `Outcome`; el peso y la severidad máxima están en el catálogo.
3. **Un check nuevo debe decidir explícitamente** cuándo es `not_applicable` y cuándo `not_tested`. Usa `responseLevel` / `htmlOnly`.
4. **Nada del sitio analizado se interpreta como HTML en la interfaz** (sin `dangerouslySetInnerHTML`).
5. **La interfaz no puede usar el atributo `style`**: la CSP de producción lo bloquea. Las barras y el anillo son SVG por ese motivo.
6. `lib/engine/types.ts` y `catalog.ts` no importan nada de Node: los comparte el cliente.

Guía para añadir un control: `CHECK_CATALOG.md` §3.

## 5. Pendiente y no verificado

### No verificado en infraestructura real

| Punto | Riesgo si falla | Cómo comprobarlo |
|---|---|---|
| Consultas DNS (`resolveMx/Txt/Caa`) en el runtime de Vercel | El informe de DNS/correo saldría como «error del análisis» (no penaliza) | Preview + un dominio propio |
| Sonda TLS 1.0–1.1 en el OpenSSL de Vercel | El control quedaría «no comprobado» | Ídem |
| Duración real y `maxDuration = 30` según tu plan | Cortes de la plataforma en webs lentas | Logs de Vercel |
| `x-vercel-forwarded-for`, Upstash real | Ya pendiente desde la auditoría 2; sin cambios | — |
| Firmas de bloqueo de CDN/WAF | Un bloqueo no reconocido se evaluaría como página 403 normal (confianza media) | Capturar respuestas reales en dominios propios |
| PDF impreso | Maquetación mejorable | Botón «Guardar PDF» en Chrome, Firefox y Safari |

### Decisiones de criterio que conviene que revises

- **CSP débil y nota A** (s04: 93). Ver `SCORING_MODEL.md` §9.
- **Puerto 80 cerrado = correcto.** Es defendible en seguridad; puede sorprender a quien espera una redirección.
- **Referrer-Policy ausente = informativo.** Otros escáneres lo penalizan.
- **Tope de 89** por un fallo de severidad alta y confianza alta. Hoy solo lo disparan CORS con credenciales y TLS negociado obsoleto.
- **Las notas cambian respecto a la versión desplegada.** Algunas webs subirán (API, sitios tras CDN, cabeceras duplicadas) y otras bajarán (cookies, CORS, contenido). Si alguien guardó su nota anterior, no es comparable.

### Riesgos residuales de las auditorías anteriores (siguen abiertos)

Regla WAF para `/api/analyze` · monitorización y alertas operativas · mecanismo de exclusión de dominios · privacidad y conservación de IP · coste del renderizado dinámico por *nonces* · restricción comercial del plan Hobby. Detalle y recomendación en `COST_ANALYSIS.md` y `PRO_PRODUCT_SPEC.md` §7.

Lo que **sí** queda resuelto de esa lista: automatización de CI (el flujo está escrito; se activará al hacer *push* a GitHub).

### No hecho en esta fase

- WebTrustScan Pro: cuentas, base de datos, panel, historial, monitorización, alertas, gestión de clientes, Stripe. Solo especificado.
- Borradores de política de privacidad y condiciones de uso.
- Análisis profundo con dominio verificado.
- DNSSEC, DKIM, TTL, subdominios, correlación con CVE, rastreo de páginas (decisión y motivo en `CHECK_CATALOG.md` §2).
- Estudio de mercado en profundidad: solo se han recogido precios públicos de fuentes secundarias.

## 6. Próximas tareas, por prioridad

1. Revisar el diff y commitear.
2. Analizar en local 5–10 dominios propios y anotar cualquier nota que no convenza.
3. Desplegar en Preview y repetir; comprobar DNS, sonda TLS y tiempos.
4. Crear la regla de *rate limit* del WAF y bajar el límite global.
5. Calibrar pesos con los resultados reales y añadir *fixtures* de bloqueos reales al laboratorio.
6. Decidir proveedores (autenticación, base de datos, correo) y arrancar la base de Pro: organizaciones → dominios → historial → comparador.
7. Verificación de dominio y monitorización con alertas.

## 7. Notas para quien continúe (persona u otro modelo)

- **Next.js 16**: `AGENTS.md` obliga a leer `node_modules/next/dist/docs/` antes de usar una API de Next. En esta fase no se ha añadido ninguna ruta ni API nueva del *framework*; cuando se añadan páginas de Pro, hay que leerla.
- **No analizar webs de terceros** durante el desarrollo. El laboratorio existe para no necesitarlo.
- Los tests del laboratorio usan puertos efímeros en `127.0.0.1` y certificados de `tests/lab/certs/` (claves de prueba, sin valor).
- `tests/lab/results.json` es un artefacto generado (`LAB_REPORT=1`); la tabla de `TESTING_REPORT.md` sale de ahí.
- El motor 1.x (`lib/audit/analyze.ts`, `checks.ts`, `score.ts`) está congelado a propósito para que la comparación del laboratorio siga siendo válida. Cuando deje de ser útil, se puede borrar junto con `tests/checks.test.ts`, `tests/analyze.test.ts` y `types/audit.ts`; la capa de red (`safeRequest.ts`, `ipGuard.ts`, `errors.ts`) **no** forma parte de ese motor y debe conservarse.
