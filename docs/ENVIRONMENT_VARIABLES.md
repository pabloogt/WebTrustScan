# ENVIRONMENT_VARIABLES — Variables de entorno

Plantilla sin valores: [`.env.example`](../.env.example). `.env.local` y cualquier otro `.env*` están ignorados por Git.

## 1. Variables

| Variable | ¿Secreta? | Obligatoria | Para qué |
|---|---|---|---|
| `APP_BASE_URL` | No | Sí con cuentas activadas | URL pública de la aplicación, sin barra final. Con ella se construyen los enlaces de los correos (no se usa la cabecera `Host`). |
| `ACCOUNTS_ENABLED` | No | No | Interruptor de las cuentas. Solo el valor exacto `true` las activa. Ausente o con cualquier otro valor: desactivadas, y páginas y rutas de cuentas responden 404. |
| `IP_HASH_SECRET` | **Sí** | Sí en Preview y producción | Clave (32 caracteres o más) con la que se derivan los identificadores de IP y de correo. Sin ella, en producción el servicio responde 503. Si se cambia, los contadores en curso se reinician y el arrastre de cuota de cuentas borradas deja de reconocerse. |
| `NEXT_PUBLIC_SUPABASE_URL` | No | Sí con cuentas activadas | URL del proyecto de Supabase. |
| `NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY` | No (pública) | Sí con cuentas activadas | Clave pública de Supabase. Solo permite lo que autoricen RLS y los permisos. Se acepta también `NEXT_PUBLIC_SUPABASE_ANON_KEY` (nombre antiguo). |
| `SUPABASE_SECRET_KEY` | **Sí** | Sí con cuentas activadas | Clave secreta de Supabase: **se salta RLS**. Solo la usa el servidor para la cuota, el registro de eventos y el borrado de cuenta. Se acepta también `SUPABASE_SERVICE_ROLE_KEY`. |
| `UPSTASH_REDIS_REST_URL` | No | Sí en Preview y producción | Dirección REST de la base Redis de Upstash.  Si Upstash se conectó desde el Marketplace de Vercel, vale también `KV_REST_API_URL` (y `KV_REST_API_TOKEN` para el token). Debe empezar por `https://`. |
| `UPSTASH_REDIS_REST_TOKEN` | **Sí** | Sí en Preview y producción | Token de esa base. |
| `RATE_LIMIT_ALLOW_MEMORY` | No | No | `true` permite límites en memoria por instancia en producción si no hay Upstash. No recomendado: en serverless cada instancia cuenta por separado. |
| `TRUSTED_PROXY_HOPS` | No | Solo fuera de Vercel | Número de proxies de confianza delante de la aplicación, para identificar la IP del cliente. En Vercel no hace falta. |
| `RATE_LIMIT_PER_MINUTE` | No | No | Análisis por minuto y cliente (por defecto 10). |
| `RATE_LIMIT_GLOBAL_PER_MINUTE` | No | No | Análisis por minuto en total (por defecto 120). Recomendado bajarlo a 30 mientras no haya ingresos. |

### Las que nunca deben llevar `NEXT_PUBLIC_`

`SUPABASE_SECRET_KEY`, `UPSTASH_REDIS_REST_TOKEN`, `IP_HASH_SECRET` y, en el futuro, las de Stripe. Next.js incluye en el código del navegador todo lo que empiece por `NEXT_PUBLIC_`. El código no lee ninguna variable secreta con ese prefijo (hay un test que lo comprueba para la clave de Supabase).

### Correo

Resend no necesita variables en la aplicación: su SMTP se configura dentro de Supabase (`SETUP_SUPABASE.md`, parte B, paso 5). El remitente es el que se indique allí; no hay ningún dominio escrito en el código.

### Stripe — fase futura, no configurar

`STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, `STRIPE_PRICE_PRO_MONTHLY`, `STRIPE_PRICE_PRO_YEARLY`. El código actual no las lee. Ver `STRIPE_NEXT_PHASE.md`.

## 2. Entornos

Tres entornos, **cada uno con sus propios servicios**. Una prueba en local o en Preview nunca debe poder tocar datos de producción.

| | Desarrollo local | Preview de Vercel | Producción de Vercel |
|---|---|---|---|
| Dónde se definen | `.env.local` | Vercel → Environment Variables → **Preview** | Vercel → Environment Variables → **Production** |
| Supabase | El local (`npx supabase start`) | Proyecto `webtrustscan-preview` | Otro proyecto distinto, cuando se autorice |
| Upstash | No hace falta (memoria) | Una base de pruebas | Otra base distinta |
| `IP_HASH_SECRET` | No hace falta | Una clave | Otra clave distinta |
| `APP_BASE_URL` | `http://localhost:3000` | La URL de Preview | El dominio definitivo |
| `ACCOUNTS_ENABLED` | `true` | `true` para probar | **Sin definir** hasta que se autorice |
| Correo | Bandeja local, nada sale | Resend, a direcciones propias | Resend |

En local, sin Upstash, los límites funcionan en memoria. En cualquier entorno con `NODE_ENV=production` o `VERCEL=1` —Preview incluido— Upstash e `IP_HASH_SECRET` son obligatorios.

## 3. Qué pasa si falta algo

| Situación | Comportamiento |
|---|---|
| `ACCOUNTS_ENABLED` distinto de `true` | Cuentas en 404; el analizador público funciona. No se crea ningún cliente de Supabase. |
| Cuentas activadas sin variables de Supabase | Rutas de cuentas: 503. El analizador público sigue funcionando como anónimo. |
| Producción sin Upstash | Analizador y rutas de cuentas: 503 «El servicio no está disponible». El motivo va al log, no al cliente. |
| Producción sin `IP_HASH_SECRET` o con menos de 32 caracteres | Igual: 503. |
| Upstash configurado pero caído | Límites en memoria local, con un aviso por minuto en el log. |
| Producción sin `APP_BASE_URL` y con cuentas activadas | El alta y la recuperación fallan con 500 (no se pueden construir los enlaces). |

Ningún mensaje de error incluye el valor de una variable.

## 4. Dónde obtener cada valor

| Variable | Dónde |
|---|---|
| `IP_HASH_SECRET` | Genérala tú: `openssl rand -hex 32` (o cualquier generador de 64 caracteres aleatorios). Una distinta por entorno. |
| Supabase (las tres) | Supabase Dashboard → tu proyecto → **Project Settings → API Keys** (URL en **Data API**). En local: `npm run supabase:status`. |
| Upstash (las dos) | <https://console.upstash.com> → **Redis → Create Database** (tipo *Regional*, región de la UE, plan Free) → pestaña **REST API** → copia `UPSTASH_REDIS_REST_URL` y `UPSTASH_REDIS_REST_TOKEN`. |
| `APP_BASE_URL` | La dirección con la que se abre la aplicación en ese entorno. |

En Vercel: **Project → Settings → Environment Variables → Add**. Marca **solo** el entorno que corresponda (Preview o Production) y, para las secretas, la opción *Sensitive*.
