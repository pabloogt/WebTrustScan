# Desarrollo local de WebTrustScan Pro

## Arranque

```bash
npm install
npm run dev
```

Sin `DATABASE_URL`, el servidor de desarrollo usa **PGlite** (PostgreSQL embebido) y guarda los datos en `.data/pglite/` (ignorado por Git). No hace falta instalar ni contratar ninguna base de datos. Para empezar de cero, borra esa carpeta con el servidor parado.

- `/acceso` — iniciar sesión o crear cuenta.
- `/panel` — dominios, verificación, historial y comparación.

## Cuenta de prueba local

Solo existe en la base de datos local de quien la haya creado; no es una credencial de ningún servicio real.

| Campo | Valor |
|---|---|
| Correo | `demo@webtrustscan.test` |
| Contraseña | `prueba-local-webtrustscan-2026` |

Si la carpeta `.data/` se ha borrado, créala de nuevo desde `/acceso` → «Crear cuenta».

## Cambiar el plan de una organización (mientras no haya pagos)

El plan vive en `organizations.plan` (`free`, `pro`, `agency`). Hasta que exista Stripe se cambia a mano. Con el servidor parado:

```bash
node -e "import('@electric-sql/pglite').then(async ({PGlite})=>{const db=new PGlite('.data/pglite');console.log((await db.query(\"update organizations set plan='pro' returning name, plan\")).rows);await db.close()})"
```

## Producción

Define `DATABASE_URL` con la cadena de conexión de cualquier PostgreSQL (ver opciones y costes en `PRO_SERVICES.md`). Las migraciones de `lib/pro/schema.ts` se aplican solas al primer uso. Sin `DATABASE_URL`, en producción las rutas de cuenta responden 503 y el analizador público sigue funcionando.
