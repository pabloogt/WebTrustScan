# SETUP_SUPABASE — Base de datos y autenticación

**Estado (16-11-2026):** el esquema, las políticas RLS y las funciones están escritos y **probados sobre PostgreSQL** (mismo SQL, 42 pruebas). **No se ha arrancado Supabase** —ni en local ni en la nube— porque en el equipo donde se desarrolló no está instalado Docker Desktop. Todo lo que dependa de Supabase Auth está implementado pero sin verificar contra el servicio real.

## Parte A · Supabase en local (Docker)

### 1. Requisitos

| Herramienta | Para qué | Cómo comprobarla |
|---|---|---|
| Docker Desktop | Ejecuta PostgreSQL, Auth y el resto de servicios locales | `docker --version` y que el icono de Docker esté «Running» |
| Node.js 20.9 o superior | La aplicación y la CLI de Supabase vía `npx` | `node -v` |
| Supabase CLI | Arranca el entorno, aplica migraciones, genera tipos | `npx supabase --version` (no hace falta instalarla aparte) |
| Visual Studio Code | Editor | — |

Instalar Docker Desktop: descárgalo de <https://www.docker.com/products/docker-desktop/>, instálalo con las opciones por defecto (usa WSL 2), reinicia si lo pide y ábrelo una vez hasta que indique que está en marcha.

### 2. Inicializar

Ya está hecho: el repositorio contiene `supabase/config.toml` (generado con `supabase init`, CLI 3.1.0, y ajustado), `supabase/migrations/`, `supabase/templates/` y `supabase/seed.sql`. No vuelvas a ejecutar `supabase init`.

Ajustes aplicados sobre la configuración por defecto, todos en `supabase/config.toml`:

| Clave | Valor | Motivo |
|---|---|---|
| `auth.site_url` | `http://localhost:3000` | Base de los enlaces de los correos |
| `auth.additional_redirect_urls` | `…/auth/confirm` | Único destino permitido tras un enlace |
| `auth.minimum_password_length` | `10` | Igual que valida la aplicación |
| `auth.email.enable_confirmations` | `true` | Sin correo confirmado no hay sesión, y el alta no revela si una cuenta existe |
| `auth.email.secure_password_change` | `true` | Cambiar la contraseña exige una sesión reciente |
| `auth.email.double_confirm_changes` | `true` (por defecto) | El cambio de correo se confirma en la dirección antigua y en la nueva |
| `auth.email.max_frequency` | `60s` | Un correo por minuto y cuenta como mucho |
| `auth.email.template.*` | Plantillas en español | Enlaces a `/auth/confirm` de la aplicación |
| `realtime`, `storage`, `edge_runtime`, `analytics` | `enabled = false` | No se usan |

### 3. Arrancar

```bash
npm run supabase:start
```

La primera vez descarga las imágenes (varios minutos). Al terminar muestra las direcciones y las claves locales. Para verlas de nuevo:

```bash
npm run supabase:status
```

Crea `.env.local` copiando `.env.example` y rellena, con lo que muestra ese comando:

| Variable | Valor en local |
|---|---|
| `NEXT_PUBLIC_SUPABASE_URL` | «API URL» (normalmente `http://127.0.0.1:54321`) |
| `NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY` | «Publishable key» (o «anon key») |
| `SUPABASE_SECRET_KEY` | «Secret key» (o «service_role key») |
| `ACCOUNTS_ENABLED` | `true` |
| `APP_BASE_URL` | `http://localhost:3000` |

Son claves del entorno local: no dan acceso a nada fuera de tu equipo.

```bash
npm run dev
```

Abre <http://localhost:3000/acceso>.

### 4. Crear un usuario de pruebas

No hay usuarios ni contraseñas de ejemplo. Crea el tuyo:

1. En `/acceso`, pestaña «Crear cuenta», con cualquier correo (por ejemplo el tuyo) y una contraseña de 10 o más caracteres.
2. Abre la bandeja local de correo en <http://127.0.0.1:54324> (ningún mensaje sale de tu equipo).
3. Abre el mensaje «Confirma tu cuenta de WebTrustScan» y pulsa el botón.

Para probar el plan Pro en local: `supabase/dev/set-plan.sql` (ver `PLANS_AND_QUOTAS.md`).

### 5. Migraciones

| Acción | Comando |
|---|---|
| Aplicar las migraciones pendientes al entorno local | `npx supabase migration up` |
| Borrar la base local y recrearla desde cero (migraciones + `seed.sql`) | `npm run supabase:reset` |
| Crear una migración nueva | `npx supabase migration new nombre_del_cambio` |
| Ver qué migraciones están aplicadas | `npx supabase migration list` |

Nunca edites una migración ya aplicada en la nube: añade otra.

### 6. Pruebas de seguridad de la base de datos

```bash
npm run test:db
```

Aplica `supabase/migrations/*.sql` sobre un PostgreSQL embebido y ejecuta 42 pruebas: aislamiento entre dos usuarios, imposibilidad de cambiar plan, rol o consumo, permisos del visitante sin sesión, cuota atómica, periodos UTC y borrado en cascada. **No necesita Docker.** El detalle está en `SECURITY_ACCOUNTS.md`.

Lo que estas pruebas no cubren: Supabase Auth, la API REST de Supabase y la concurrencia real entre varias conexiones (el motor embebido usa una sola).

### 7. Tipos TypeScript

```bash
npm run supabase:types
```

Genera `lib/accounts/database.types.ts` a partir del esquema local. **Pendiente:** no se ha podido ejecutar sin Docker. Hoy la aplicación usa tipos escritos a mano en `lib/accounts/supabasePorts.ts`; cuando generes el fichero conviene tipar con él el cliente de Supabase.

### 8. Detener

```bash
npm run supabase:stop
```

Los datos locales se conservan entre arranques. Para borrarlos también: `npx supabase stop --no-backup`.

### Datos de la fase anterior

La carpeta `.data/pglite/` (39 MB) contiene la cuenta y las auditorías de prueba del sistema de cuentas anterior, que ya no existe. La aplicación no la lee. No se ha borrado: puedes eliminarla a mano cuando quieras. Esas cuentas no se migran: sus contraseñas usaban otro sistema y no se pueden trasladar; quien tuviera una tendría que registrarse de nuevo.

## Parte B · Proyecto en la nube

Pasos para ti, en este orden. No crees nada hasta que decidas publicar las cuentas en Preview.

1. **Crear el proyecto.** Entra en <https://supabase.com/dashboard>, pulsa **New project**, elige tu organización y:
   - *Name:* `webtrustscan-preview` (crea otro distinto para producción más adelante).
   - *Database Password:* pulsa **Generate a password** y guárdala en tu gestor de contraseñas. No la necesita la aplicación.
   - *Region:* una de la Unión Europea, por ejemplo **West EU (Ireland)** o **Central EU (Frankfurt)**.
   - Plan **Free**.
2. **Aplicar el esquema.** En tu equipo:
   ```bash
   npx supabase login
   ```
   ```bash
   npx supabase link --project-ref TU_PROJECT_REF
   ```
   ```bash
   npx supabase db push
   ```
   `TU_PROJECT_REF` es el código que aparece en la URL del panel (`…/project/abcdefghijklmnop`). `db push` enseña las migraciones que va a aplicar y pide confirmación.
3. **Comprobar RLS.** En el panel: **Database → Tables**. Las once tablas de `public` deben mostrar «RLS enabled». Después **Advisors → Security Advisor**: no debe haber avisos de tablas sin RLS.
4. **Autenticación.** En **Authentication**:
   - **URL Configuration** → *Site URL:* la URL pública de la aplicación (la de Preview). *Redirect URLs:* añade `https://TU-DOMINIO/auth/confirm`.
   - **Sign In / Providers → Email:** activa *Confirm email*, *Secure email change* y *Secure password change*; *Minimum password length:* `10`. Si aparece *Prevent use of leaked passwords*, actívalo (puede requerir un plan de pago).
   - **Emails → Templates:** en *Confirm signup*, *Reset password* y *Change email address*, pega el HTML de `supabase/templates/confirmation.html`, `recovery.html` y `email_change.html`, con sus asuntos (están en `supabase/config.toml`).
   - **Rate Limits:** deja los valores por defecto; la aplicación aplica además los suyos.
5. **Correo con Resend.** Sin SMTP propio, Supabase solo envía un puñado de correos por hora y únicamente a miembros del proyecto.
   - En <https://resend.com> crea la cuenta, entra en **Domains → Add Domain** y añade el dominio desde el que enviarás (por ejemplo un subdominio como `correo.tudominio.com`). Resend te dará varios registros DNS (SPF y DKIM): créalos en tu proveedor de dominio y espera a que aparezca «Verified».
   - En **API Keys → Create API Key** crea una clave con permiso *Sending access*.
   - En Supabase: **Authentication → Emails → SMTP Settings → Enable Custom SMTP**:

     | Campo | Valor |
     |---|---|
     | Sender email | una dirección del dominio verificado, p. ej. `no-reply@correo.tudominio.com` |
     | Sender name | `WebTrustScan` |
     | Host | `smtp.resend.com` |
     | Port | `465` |
     | Username | `resend` |
     | Password | la API key de Resend |

   El dominio remitente no está decidido: no hay ninguno escrito en el código ni en la configuración.
6. **Claves para Vercel.** En **Project Settings → API Keys** copia la *Project URL*, la *Publishable key* y la *Secret key* a las variables indicadas en `ENVIRONMENT_VARIABLES.md`, **solo en el entorno Preview**.

### Sesiones

| Ajuste | Valor | Dónde |
|---|---|---|
| Duración del token de acceso | 1 hora | `jwt_expiry` |
| Renovación | Automática, con rotación del token de renovación | `enable_refresh_token_rotation` |
| Reutilización de un token ya rotado | 10 s de margen; después se revoca la sesión | `refresh_token_reuse_interval` |
| Caducidad por inactividad y duración máxima | **Sin definir.** En Supabase son opciones de pago (*Authentication → Sessions*). Recomendado al activarlas: 7 días de inactividad y 30 de duración máxima | Panel |
| MFA (TOTP) | Desactivado. Supabase lo ofrece de serie; conviene exigirlo a las cuentas de administrador antes de darles ninguna función | `auth.mfa.totp` |

## Parte C · La recuperación de contraseña no funciona: cómo diagnosticarlo

La aplicación no puede ver la configuración ni los registros del proyecto en la nube. Comprueba, en este orden:

1. **Plantilla *Reset password*** (*Authentication → Emails → Templates*). Debe ser la de `supabase/templates/recovery.html`, cuyo enlace es `{{ .SiteURL }}/auth/confirm?token_hash={{ .TokenHash }}&type=recovery&next=/cuenta/nueva-contrasena`. Con la plantilla predeterminada (`{{ .ConfirmationURL }}`) el enlace pasa primero por Supabase y vuelve con `?code=`; la aplicación lo acepta, pero **solo en el mismo navegador** donde se pidió la recuperación (flujo PKCE). Si se abre en otro dispositivo, fallará.
2. **URL Configuration.** *Site URL* = la URL pública de la aplicación (sin barra final). *Redirect URLs* debe incluir `https://TU-DOMINIO/auth/confirm`. Si la dirección no está permitida, Supabase redirige a la *Site URL* y el enlace no llega a la aplicación.
3. **Registros de Auth** (*Logs → Auth*). Busca la hora de la solicitud:
   - `over_email_send_rate_limit` o `email rate limit exceeded`: se ha alcanzado el tope de correos. Sin SMTP propio, Supabase envía muy pocos por hora. **Esta es la causa más probable de que «el segundo correo no llegue».** Solución: SMTP propio (Resend, Parte B, paso 5).
   - `For security purposes, you can only request this after N seconds`: se pidió otro correo antes de 60 s (`max_frequency`). La pantalla ya obliga a esperar.
   - `otp_expired` / `One-time token not found`: el enlace ya se usó, caducó o se pidió otro después (solo vale el último).
4. **Registro de la aplicación** (logs de Vercel). Cuando no se envía un correo se escribe `Recuperación: no se ha enviado el correo.` con el motivo (`cooldown_60s`, `app_hourly_limit` o `provider:<código de Supabase>`), nunca el correo. Lo mismo queda en `security_events` como `recovery_not_sent`.
5. **Filtros de correo.** Algunos antispam abren los enlaces para analizarlos. Antes, eso gastaba el token y el usuario veía «ha caducado». Ahora `/auth/confirm` exige pulsar un botón; si aun así ocurre, el registro de Auth mostrará un canje que el usuario no hizo.

No hace falta cambiar la caducidad de los enlaces (1 hora) ni desactivar ninguna protección.
