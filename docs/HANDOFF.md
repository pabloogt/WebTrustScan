# HANDOFF — Estado y cómo continuar

**Actualizado:** 15 de noviembre de 2026 · **Rama de trabajo:** `engine-2.0-revision` · **Copia de seguridad previa:** etiqueta `backup/pre-revision-2026-11-15` (commit `69ae5b1`).

## 1. Estado en una frase

El analizador público (Engine 2.0) está revisado y verificado en local; el sistema de cuentas existe, está auditado y **está desactivado por defecto**; no hay nada desplegado ni ningún servicio externo conectado.

## 2. Git

| Rama / etiqueta | Contenido |
|---|---|
| `main` | Versión desplegada, sin Engine 2.0 |
| `engine-2.0` | Engine 2.0 (`1df13dc`) + calibración, PDF y cuentas (`69ae5b1`). Existe también en `origin`. |
| `backup/pre-revision-2026-11-15` | Etiqueta local sobre `69ae5b1`, estado anterior a esta revisión |
| `engine-2.0-revision` | Esta revisión. **Cambios sin commitear** hasta que lo pidas. |

No hay credenciales en el repositorio. Lo único con forma de secreto es la clave privada de prueba del laboratorio (`tests/lab/certs/server.key`), que no protege nada. `docs/DESARROLLO_LOCAL.md` contiene la contraseña de una cuenta de prueba que solo existe en una base de datos local.

## 3. Qué hay implementado

**Activo:**

- Analizador público: `/` y `POST /api/analyze`, con 24 controles, informe con vistas resumen y técnica, descarga de PDF, impresión y exportación a JSON.
- Protecciones de las auditorías 1 y 2: SSRF, *rebinding*, límites de peticiones, CSP con *nonces*.

**Implementado y desactivado** (`ACCOUNTS_ENABLED` distinto de `true`):

- Registro, acceso y sesiones; organizaciones y roles; dominios guardados y verificación de propiedad; auditorías guardadas, historial y comparación; pantallas `/acceso` y `/panel`. Detalle y carencias: `AUTH_STORAGE_AUDIT.md`.

**No implementado (pospuesto por decisión tuya):** pagos y Stripe, suscripciones, precios, monitorización programada, alertas por correo, gestión de clientes, marca blanca, análisis profundo. Ningún servicio externo contratado ni conectado.

## 4. Cómo verificar

```bash
npm ci
npm test
npm run typecheck
npm run lint
npm run build
```

Esperado: 492 pruebas en verde, sin errores de tipos ni de lint, build correcto.

Para ver el analizador: `npm run dev` y analizar un dominio propio. Para ver las cuentas en local: crear `.env.local` con `ACCOUNTS_ENABLED=true` (ver `DESARROLLO_LOCAL.md`).

## 5. Arquitectura que conviene no romper

1. **Toda salida a red pasa por `lib/audit/safeRequest.ts`** (`safeFetch`, `safeTlsProbe`). Los controles no abren conexiones: leen el `ScanContext`.
2. **Los controles no conocen los pesos**: están en el catálogo.
3. **Un control decide de forma explícita** cuándo es `not_applicable`, `not_tested` o `info`, y con qué confianza.
4. **Un error del analizador nunca se convierte en un fallo del sitio.** En TLS, «no comprobable» no es «rechazado».
5. **Los textos describen lo que se ha observado**, no lo que harán terceros (receptores de correo, navegadores antiguos).
6. **Las recomendaciones no proponen cambios que no se han podido comprobar** (`includeSubDomains`, una CSP concreta).
7. **Nada del sitio analizado se interpreta como HTML** en la interfaz, y la interfaz no usa el atributo `style` (lo bloquea la CSP).
8. **Las rutas de cuentas se crean con `route()`** (`lib/pro/http.ts`), que aplica el interruptor, la comprobación de origen y la traducción de errores. Una ruta nueva que no lo use quedaría expuesta.

## 6. Pendiente antes de una beta pública del analizador

Imprescindible:

1. **Revisar y commitear** esta revisión.
2. **Desplegar en Preview** (requiere tu autorización) y comprobar: consultas DNS, las cuatro sondas TLS, duración real por análisis y `maxDuration`.
3. **Regla de límite de peticiones en el WAF de Vercel** para `/api/analyze`, y bajar `RATE_LIMIT_GLOBAL_PER_MINUTE`. Lo tienes que hacer tú en tu cuenta.
4. **Calibrar con 20–30 dominios propios o autorizados**: dos sitios no bastan para dar por buenas las heurísticas.
5. **Mecanismo de exclusión y contacto de abuso**: una dirección visible y una lista de dominios que no se analizan.
6. **Textos legales mínimos**: aviso legal y política de privacidad (el analizador trata la URL y un hash temporal de la IP).
7. **Alertas de gasto y de errores** en Vercel.
8. **Confirmar el plan de Vercel**: Hobby es solo para uso no comercial.

Recomendable:

- Guardar el PDF desde varios navegadores y abrirlo en varios visores.
- Capturar respuestas reales de bloqueo de CDN/WAF y añadirlas al laboratorio.
- Investigar el test de límite de peticiones que falló una vez.

## 7. No verificado

Ver `TESTING_REPORT.md` §4. En resumen: nada en Vercel, cuentas sobre PostgreSQL real, cookie de sesión en HTTPS, guardado real del PDF en disco y más de dos sitios reales.

## 8. Documentación

| Documento | Estado |
|---|---|
| `SCORING_MODEL.md`, `CHECK_CATALOG.md`, `TESTING_REPORT.md`, `CALIBRATION_REPORT.md`, `AUTH_STORAGE_AUDIT.md`, `HANDOFF.md`, `DESARROLLO_LOCAL.md`, `SECURITY_METHODOLOGY.md` | **Vigentes**, actualizados en esta revisión |
| `ENGINE_DIAGNOSIS.md` | Histórico: diagnóstico del motor 1.x. Sus cifras del Engine 2.0 son las de entonces. |
| `PRO_PRODUCT_SPEC.md`, `PRO_SERVICES.md`, `COST_ANALYSIS.md`, `ROADMAP.md` | **Planificación pospuesta.** No describen el estado actual ni autorizan desarrollo. Llevan un aviso al principio. |
| `informes/` | Informes reales del 15-11-2026 (JSON y PDF) de los dos casos de calibración |

## 9. Notas para quien continúe

- `AGENTS.md` obliga a consultar `node_modules/next/dist/docs/` antes de usar una API de Next 16.
- No analizar webs de terceros durante el desarrollo: para eso está el laboratorio. Los dos casos reales se han usado porque el propietario del proyecto lo pidió.
- El motor 1.x (`lib/audit/analyze.ts`, `checks.ts`, `score.ts`) está congelado para la comparación del laboratorio. La capa de red (`safeRequest.ts`, `ipGuard.ts`, `errors.ts`) no forma parte de él y debe conservarse.
- En Git Bash de esta máquina los *heredocs* largos con comillas y acentos fallan: para ediciones con script, escribir el fichero y ejecutarlo.
