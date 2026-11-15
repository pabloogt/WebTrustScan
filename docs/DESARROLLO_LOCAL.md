# Desarrollo local de WebTrustScan Pro

> Las cuentas están **desactivadas por defecto**. Sin el paso «Activar las cuentas», `/acceso`, `/panel` y toda su API responden 404 y solo funciona el analizador público.

## Arranque

```bash
npm install
npm run dev
```

Sin `DATABASE_URL`, el servidor de desarrollo usa **PGlite** (PostgreSQL embebido) y guarda los datos en `.data/pglite/` (ignorado por Git). No hace falta instalar ni contratar ninguna base de datos. Para empezar de cero, borra esa carpeta con el servidor parado.

## Activar las cuentas en local

Crea un fichero `.env.local` en la raíz (está ignorado por Git) con:

```
ACCOUNTS_ENABLED=true
```

y reinicia `npm run dev`. Solo el valor exacto `true` las activa. No lo definas en producción: el sistema de cuentas no está listo para uso público (ver `AUTH_STORAGE_AUDIT.md`).

Con las cuentas activadas:

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

Hoy no se debe activar. Si en el futuro se hace, harán falta dos variables de servidor: `ACCOUNTS_ENABLED=true` y `DATABASE_URL` con la cadena de conexión de un PostgreSQL. Las migraciones de `lib/pro/schema.ts` se aplican solas al primer uso. Sin `ACCOUNTS_ENABLED=true` las rutas de cuenta responden 404; con ella pero sin `DATABASE_URL`, 503. El analizador público funciona en todos los casos.
