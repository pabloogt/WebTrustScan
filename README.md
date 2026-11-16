# WebTrustScan

Auditoría externa de la configuración de seguridad de una web. Introduces una URL y el **Engine 2.0** revisa cifrado y certificado, cabeceras del navegador, cookies, CORS, contenido de la página y, en un informe aparte, la autenticación del correo y el DNS.

Cada hallazgo lleva severidad, evidencia y solución. La puntuación (0–100, nota A–F) va acompañada de la **cobertura** (qué parte de los controles aplicables se pudo comprobar) y de la **confianza** del resultado.

No es una prueba de intrusión ni una certificación: evalúa lo observable desde fuera, sin autenticarse y con un máximo de cinco peticiones inocuas y un saludo TLS por versión de protocolo.

Las cuentas (historial de análisis, planes Free y Pro con cuota) usan Supabase y están **desactivadas por defecto**: solo el analizador es público. Ver [`docs/HANDOFF.md`](docs/HANDOFF.md).

## Qué comprueba

24 controles definidos en un catálogo central (`lib/engine/catalog.ts`):

| Categoría | Controles |
| --- | --- |
| Cifrado y transporte | HTTPS, certificado, versión TLS, TLS 1.0/1.1, redirección HTTP → HTTPS, HSTS |
| Protecciones del navegador | CSP, clickjacking, `nosniff`, Referrer-Policy, Permissions-Policy, aislamiento entre orígenes |
| Cookies y sesión | `Secure`, `HttpOnly`, `SameSite` |
| Acceso entre orígenes | Política CORS |
| Contenido de la página | Contenido mixto, formularios sin cifrar, SRI |
| Exposición de información | Versiones en cabeceras, `security.txt` |
| Correo y DNS (informe aparte, evaluación limitada) | SPF, DMARC, CAA (informativo) |

Estados posibles de un control: correcto, mejorable, fallo, informativo, **no aplica**, **no comprobado** y **error del análisis**. Solo los tres primeros puntúan: lo que no aplica a una web no cuenta, y lo que no se pudo comprobar reduce la cobertura, no la nota.

Documentación en [`docs/`](docs/):

| Documento | Contenido |
| --- | --- |
| [ENGINE_DIAGNOSIS.md](docs/ENGINE_DIAGNOSIS.md) | Anomalías del motor 1.x, reproducidas |
| [SCORING_MODEL.md](docs/SCORING_MODEL.md) | Fórmula, pesos, topes, cobertura y confianza |
| [SECURITY_METHODOLOGY.md](docs/SECURITY_METHODOLOGY.md) | Alcance, niveles de comprobación y estándares |
| [CHECK_CATALOG.md](docs/CHECK_CATALOG.md) | Controles implementados, aprobados y descartados |
| [TESTING_REPORT.md](docs/TESTING_REPORT.md) | Laboratorio y verificación |
| [CALIBRATION_REPORT.md](docs/CALIBRATION_REPORT.md) | Calibración con dos análisis reales |
| [SETUP_SUPABASE.md](docs/SETUP_SUPABASE.md) | Base de datos y autenticación: local y nube |
| [SECURITY_ACCOUNTS.md](docs/SECURITY_ACCOUNTS.md) | Autenticación, sesiones, roles, RLS y pruebas de aislamiento |
| [PLANS_AND_QUOTAS.md](docs/PLANS_AND_QUOTAS.md) | Free, Pro, consumo y prevención de abuso |
| [ENVIRONMENT_VARIABLES.md](docs/ENVIRONMENT_VARIABLES.md) | Variables y entornos |
| [STRIPE_NEXT_PHASE.md](docs/STRIPE_NEXT_PHASE.md) | Facturación, fase futura |
| [HANDOFF.md](docs/HANDOFF.md) | Estado actual y continuidad |
| [PRO_PRODUCT_SPEC.md](docs/PRO_PRODUCT_SPEC.md) · [PRO_SERVICES.md](docs/PRO_SERVICES.md) · [COST_ANALYSIS.md](docs/COST_ANALYSIS.md) · [ROADMAP.md](docs/ROADMAP.md) | Planificación comercial, **pospuesta** |

## Desarrollo

Requiere Node.js 20.9 o superior.

```bash
npm install
npm run dev        # http://localhost:3000
```

| Comando | Qué hace |
| --- | --- |
| `npm run dev` | Servidor de desarrollo |
| `npm run build` / `npm start` | Build y servidor de producción |
| `npm test` | Tests (Vitest) |
| `npm run test:lab` | Solo el laboratorio de escenarios (motor 1.x frente a 2.0) |
| `npm run test:db` | RLS, permisos y cuota sobre PostgreSQL (no necesita Docker) |
| `npm run test:accounts` | Flujos de cuenta, cuotas y límites |
| `npm run supabase:start` / `supabase:stop` | Supabase local (necesita Docker Desktop) |
| `npm run lint` | ESLint |
| `npm run typecheck` | Comprobación de tipos |

## Estructura

```
app/api/analyze/route.ts   Endpoint POST: valida la entrada, limita peticiones y traduce errores a HTTP
proxy.ts                   Genera el nonce y la Content-Security-Policy de cada página
lib/csp.ts                 Construcción de la Content-Security-Policy
lib/clientIp.ts            Identificación del cliente sin fiarse de cabeceras falseables
lib/rateLimit.ts           Limitador de peticiones (memoria o Upstash Redis por REST)
lib/analyzeRateLimit.ts    Límites concretos de /api/analyze (por cliente y global)
lib/normalizeUrl.ts        Validación de la URL (compartida por cliente y servidor)
lib/audit/safeRequest.ts   ÚNICA vía de salida a red: protección SSRF, timeouts, redirecciones, TLS y cuerpo acotado
lib/audit/ipGuard.ts       Lista de rangos IP no permitidos
lib/audit/{analyze,checks,score}.ts   Motor 1.x, congelado: solo lo usa el laboratorio para comparar
lib/engine/catalog.ts      Catálogo de controles: identificador, categoría, severidad, peso y referencias
lib/engine/run.ts          Orquesta el análisis: recoge el contexto y ejecuta los controles
lib/engine/checks/         Un módulo por categoría; cada control devuelve un resultado estandarizado
lib/engine/parse/          Parsers de CSP, cookies y HTML
lib/engine/scoring.ts      Puntuación, cobertura, confianza y topes (independiente de los controles)
lib/engine/dnsClient.ts    Consultas DNS (inyectables en tests)
components/report/         Informe: vistas resumen y técnica, exportación
tests/                     Suite histórica (seguridad de la capa de red, rate limiting, CSP)
tests/engine/              Scoring, parsers y regresión de seguridad del Engine 2.0
tests/lab/                 Laboratorio: sitios HTTP/HTTPS simulados y comparación entre motores
docs/                      Documentación de metodología, scoring y producto
```

## API

`POST /api/analyze` con cuerpo `{ "url": "ejemplo.com" }`.

| Estado | Significado |
| --- | --- |
| 200 | Informe (`target`, `notices`, `web`, `dnsEmail`, `findings`; ver `lib/engine/types.ts`) |
| 400 | Falta la URL, no es válida o apunta a un destino no permitido |
| 429 | Demasiadas peticiones (10 por minuto y cliente, 120 por minuto en total) |
| 502 | No se pudo conectar o el dominio no existe (un certificado no válido ya no es un error: es un hallazgo del informe) |
| 504 | La web tardó demasiado en responder |

## Configuración

Todas las variables son opcionales. En local no hace falta ninguna.

| Variable | Para qué sirve |
| --- | --- |
| `UPSTASH_REDIS_REST_URL`, `UPSTASH_REDIS_REST_TOKEN` | Contador de peticiones compartido entre instancias. Necesario en Vercel o cualquier entorno serverless. También se aceptan `KV_REST_API_URL` y `KV_REST_API_TOKEN` |
| `RATE_LIMIT_PER_MINUTE` | Análisis por minuto y cliente (por defecto 10) |
| `RATE_LIMIT_GLOBAL_PER_MINUTE` | Análisis por minuto en total (por defecto 120) |
| `TRUSTED_PROXY_HOPS` | Solo con proxy propio (Nginx, Caddy…): número de proxies de confianza delante de la app. No hace falta en Vercel |

### Despliegue en Vercel

1. Crea una base de datos Upstash Redis (el plan gratuito basta para empezar) y añade sus dos variables REST al proyecto.
2. En el panel de Vercel, en Firewall, crea una regla de rate limit para `/api/analyze` por IP. Corta el abuso antes de que llegue a la función.
3. No pongas otro proxy delante de Vercel sin revisar `lib/clientIp.ts`: la IP que vería la app sería la del proxy.

## Seguridad del analizador

El servidor hace peticiones a URLs que escribe el usuario, así que:

- Solo se admiten `http://` y `https://` en los puertos 80 y 443.
- Se rechaza cualquier destino que resuelva a IPs privadas, loopback, link-local (incluidos los metadatos cloud) o reservadas.
- La IP se valida dentro del mismo `lookup` que usa el socket, sin una segunda resolución, lo que evita DNS rebinding. Después se comprueba que el socket conectó exactamente a una IP aprobada.
- Las redirecciones se siguen a mano (máximo 5) y cada salto pasa las mismas validaciones.
- Hay un timeout de 8 s por petición (6 s en las sondas secundarias) y 20 s por análisis.
- Del cuerpo de la página se leen como mucho 512 KB, y la descompresión está acotada a 4 MB para que un sitio malicioso no pueda agotar la memoria.
- Un certificado no válido se inspecciona para poder informarlo, pero eso no relaja ninguna validación de destino.
- Las sondas de versión de TLS y todas las peticiones adicionales pasan por la misma capa (`lib/audit/safeRequest.ts`). Ningún módulo de análisis abre conexiones por su cuenta.
- Los valores de las cookies del sitio analizado se descartan y nunca aparecen en un informe.

### Límite de peticiones

- La IP del cliente solo se toma de cabeceras que el cliente no puede falsear: las de Vercel cuando `VERCEL=1`, o la posición indicada por `TRUSTED_PROXY_HOPS`. Sin ninguna de las dos, todos los clientes comparten un único cupo.
- Sin Upstash configurado el contador vive en memoria y es por instancia. Si Upstash falla, se limita en memoria en lugar de dejar pasar.
- Las IP se guardan como hash y caducan al minuto.

### Content-Security-Policy

- Cada página lleva una CSP con un nonce distinto por petición, sin `'unsafe-inline'` ni `'unsafe-eval'` en producción.
- Por eso las páginas se renderizan por petición y no se cachean en CDN.
- No uses atributos `style` ni etiquetas `<style>` en línea en componentes nuevos: la CSP los bloquea. Usa clases de Tailwind.

### Limitaciones conocidas

- El almacén de Upstash está probado contra un servidor que imita su API, no contra el servicio real.
- La ventana del límite es fija: en el cambio de minuto un cliente puede hacer hasta el doble de su cupo.
- Un atacante con muchas IP reales solo queda acotado por el límite global.
- `package.json` fuerza `minimatch` 11 dentro de `typescript-estree` para corregir un aviso de seguridad; se puede quitar cuando `typescript-eslint` lo actualice.
