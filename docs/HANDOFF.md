# HANDOFF — Estado del proyecto y cómo continuar

**Actualizado:** 16 de noviembre de 2026 · **Rama:** `engine-2.0-revision` · **Commit de partida de esta fase:** `2009403` · **Cambios de esta fase: sin commitear.**

## 1. Estado en una frase

El analizador está revisado y protegido con límites nuevos; las cuentas se han rehecho sobre Supabase Auth y PostgreSQL con RLS, con planes Free y Pro y consumo atómico, y **la base de datos está probada pero Supabase no se ha llegado a arrancar** (falta Docker en el equipo de desarrollo). Nada está desplegado ni conectado a un servicio externo.

**Clasificación: preparado para pruebas locales.** Ver §7.

## 2. Git

| Rama / etiqueta | Contenido |
|---|---|
| `main` | Versión antigua desplegada |
| `engine-2.0` (local y `origin`) | Engine 2.0 + calibración + primera versión de cuentas (`69ae5b1`) |
| `engine-2.0-revision` (local y `origin`) | Revisión técnica (`2009403`) |
| `backup/pre-revision-2026-11-15` | Etiqueta local sobre `69ae5b1` |
| **Árbol de trabajo** | Esta fase, sin commitear: no está en GitHub |

No se ha hecho commit, push, merge ni despliegue. No hay credenciales en el árbol de trabajo. El historial de Git conserva, en commits anteriores, la contraseña de una cuenta de demostración que solo existía en una base de datos local; no da acceso a nada.

## 3. Qué hay y en qué estado

| Pieza | Estado |
|---|---|
| Analizador público (`/`, `POST /api/analyze`), Engine 2.0, PDF | **Probado localmente** |
| Límite de 2 análisis diarios por IP sin cuenta; 503 en producción sin Upstash | **Probado localmente** |
| Esquema PostgreSQL, RLS, permisos, consumo atómico | **Probado localmente sobre PostgreSQL**; sin verificar en Supabase |
| Autenticación con Supabase Auth (alta, confirmación, acceso, recuperación, cambios, borrado) | **Implementado; lógica propia probada con un doble; sin verificar contra Supabase** |
| Panel, configuración y plan | **Implementado; no abierto en el navegador con datos reales** |
| Planes Free y Pro, capacidades centralizadas | **Probado localmente** |
| Límites con Upstash | **Implementado; sin verificar contra Upstash real** |
| Plantillas de correo y configuración de Supabase | **Preparado**; sin enviar ningún correo |
| Resend | **Pendiente de configurar** |
| Vercel | **Pendiente**; nada desplegado |
| Stripe | **Fase futura**; solo tipos, tablas y documentación |
| CAPTCHA, MFA, administración, equipos | **No implementado** |
| Cuentas en producción | **Desactivadas** (`ACCOUNTS_ENABLED` sin definir) |

Retirado en esta fase, con su motivo: la autenticación propia (scrypt y sesiones en base de datos), PGlite como base de la aplicación (queda solo como motor de las pruebas), la dependencia `pg`, y los dominios guardados con verificación de propiedad y la comparación de auditorías (el producto se reorienta al historial de análisis por cuenta; un sistema basado en una lista de dominios permitía reiniciar el consumo).

## 4. Mapa del código

```
lib/audit/            Capa de red segura (SSRF, rebinding, tiempos). No tocar a la ligera.
lib/engine/           Engine 2.0: catálogo, controles, puntuación.
lib/report/pdf.ts     Informe PDF.
lib/plans.ts          ÚNICA fuente de planes, cuotas y límites.
lib/limits.ts         Límites de frecuencia y concurrencia (Upstash / memoria / no disponible).
lib/accounts/
  config.ts           Interruptor ACCOUNTS_ENABLED y configuración de Supabase.
  ports.ts            Interfaces: autenticación, datos, cuota.
  supabasePorts.ts    Implementación sobre Supabase (única parte que conoce el SDK).
  service.ts          Lógica de cuentas (no enumeración, límites, validación).
  analyze.ts          Consumo alrededor del motor: visitante y usuario.
  http.ts             Envoltorio de rutas: interruptor, origen, errores.
lib/billing/          Solo tipos para la futura integración de pagos.
supabase/             config.toml, migraciones, plantillas de correo, seed vacío.
proxy.ts              CSP con nonce y renovación de la sesión.
tests/db/             Migraciones reales sobre PostgreSQL embebido: RLS y cuota.
tests/accounts/       Rutas reales con un doble de Supabase Auth.
```

Reglas que conviene no romper:

1. Toda ruta de cuentas se crea con `route()`: aplica el interruptor **antes** de crear ningún cliente de Supabase, exige mismo origen y traduce errores.
2. El navegador no habla con Supabase. Si algún día lo hace, hay que revisar la CSP y las cookies (hoy `HttpOnly`).
3. La clave secreta solo se usa en `quotaPort` y en el borrado de cuenta.
4. Ningún límite ni plan se escribe fuera de `lib/plans.ts`.
5. Una migración aplicada no se edita: se añade otra.
6. Los planes cambian cuánto se puede analizar, nunca las protecciones del motor.
7. La interfaz no usa el atributo `style` (lo bloquea la CSP).

## 5. Cómo verificar

```bash
npm ci
npm test
npm run typecheck
npm run lint
npm run build
```

Esperado: 539 pruebas en verde. Para arrancar Supabase y las cuentas en local: `SETUP_SUPABASE.md`, parte A.

## 6. Lo que tienes que hacer tú, en orden

### A. Para pasar a pruebas locales completas

1. **Revisar y commitear** esta fase (o pedírmelo).
2. **Instalar Docker Desktop** (<https://www.docker.com/products/docker-desktop/>), con las opciones por defecto, y abrirlo hasta que indique que está en marcha.
3. En la carpeta del proyecto: `npm run supabase:start`. La primera vez tarda varios minutos.
4. Copiar `.env.example` a `.env.local` y rellenar las tres variables de Supabase con lo que muestra `npm run supabase:status`; poner `ACCOUNTS_ENABLED=true` y `APP_BASE_URL=http://localhost:3000`.
5. `npm run dev`, abrir <http://localhost:3000/acceso>, crear una cuenta y confirmar el correo en <http://127.0.0.1:54324>.
6. Recorrer: acceso, análisis con cuenta (hasta agotar los 5), historial, descarga de PDF, cambio de contraseña, recuperación, cambio de correo, exportación y borrado. **Anotar cualquier fallo**: es la primera vez que este código se ejecuta contra Supabase.
7. `npm run supabase:types` y avisarme para tipar el cliente con el resultado.

### B. Para un Preview privado

8. **Supabase en la nube:** `SETUP_SUPABASE.md`, parte B (proyecto en región de la UE, `db push`, comprobar RLS, ajustes de autenticación, plantillas).
9. **Resend:** cuenta, dominio de envío verificado y SMTP en Supabase (mismo documento, paso 5). Requiere crear registros DNS.
10. **Upstash:** <https://console.upstash.com> → *Redis* → *Create Database* (regional, UE, plan Free) → pestaña *REST API*.
11. **Vercel → Settings → Environment Variables**, solo entorno **Preview**: las variables de `ENVIRONMENT_VARIABLES.md`. Generar `IP_HASH_SECRET` con `openssl rand -hex 32`.
12. Autorizarme el despliegue de Preview, o hacerlo tú, y repasar la lista de §8.

### C. Antes de abrir el registro al público

13. Textos legales (§9) revisados por un profesional.
14. Decidir si se exige CAPTCHA.
15. Regla de límite de peticiones en el WAF de Vercel y alertas de gasto.
16. Programar `purge_security_events()`.

**Debe quedar desactivado:** `ACCOUNTS_ENABLED` en Production; todo lo de Stripe; *Allow new users to sign up* puede dejarse activo en Preview pero conviene limitarlo a correos propios mientras no haya Resend.

## 7. Estado de lanzamiento: preparado para pruebas locales

No se puede clasificar más arriba porque:

- **Supabase Auth no se ha ejecutado nunca con este código.** Las pruebas de flujos usan un doble; pueden aparecer diferencias en códigos de error, cookies o enlaces.
- La interfaz de cuentas no se ha visto funcionar en un navegador.
- Upstash, Resend y Vercel no están configurados.

Lo que sí respalda esta categoría: el analizador y sus protecciones están intactos y probados; el esquema, RLS y la cuota están probados sobre PostgreSQL con el SQL que se desplegará; las cuentas están desactivadas por defecto y comprobado en un servidor de producción local.

Para **Preview privado** hacen falta los pasos 2 a 12. Para **beta pública**, además, los pasos 13 a 16 y una calibración del motor con más dominios. **Producción comercial** requiere Stripe y sus decisiones.

## 8. Lista de comprobación para el Preview

- [ ] Variables definidas **solo** en Preview; ninguna secreta con prefijo `NEXT_PUBLIC_`.
- [ ] Región de las funciones de Vercel en la UE, cerca de la de Supabase.
- [ ] `/api/analyze` responde 200 (y no 503): Upstash e `IP_HASH_SECRET` correctos.
- [ ] Tercer análisis sin cuenta desde la misma red → 429. Desde otra red, no.
- [ ] Duración de 20 análisis reales; ninguno cortado por la plataforma (`maxDuration = 30`).
- [ ] Las cuatro sondas TLS dan resultado o «no comprobado», no error.
- [ ] Alta → llega el correo de Resend → el enlace abre sesión y lleva a `/panel`.
- [ ] Cookies de sesión con `HttpOnly`, `Secure` y `SameSite=Lax` (herramientas del navegador → Aplicación → Cookies).
- [ ] `/panel` sin sesión redirige a `/acceso`.
- [ ] Con dos cuentas: el identificador de un informe de una no se abre desde la otra.
- [ ] Sexto análisis con una cuenta Free → 429 con el mensaje de cuota.
- [ ] Recuperación de contraseña completa; el enlace no sirve dos veces.
- [ ] «Descargar PDF» guarda un fichero que se abre; sin errores de CSP en la consola.
- [ ] En Upstash aparecen claves `wts:…` sin ninguna IP legible.
- [ ] Supabase → Advisors → Security: sin avisos.
- [ ] Production sigue sin `ACCOUNTS_ENABLED`.

## 9. Privacidad

### Qué se guarda

| Dato | Dónde | Para qué | Conservación |
|---|---|---|---|
| Correo y contraseña (hash) | Supabase Auth | Identificar la cuenta | Hasta que se elimine la cuenta |
| Nombre visible (opcional) | `profiles` | Mostrarlo en el panel | Hasta que se elimine |
| Informes de análisis | `audits` | Historial | Los 10 (Free) o 50 (Pro) más recientes; hasta que se borren o se elimine la cuenta |
| Registro de consumo | `usage_events` | Aplicar la cuota (ventana de 7 días) | Hasta que se elimine la cuenta. **No hay purga de consumos antiguos** |
| HMAC del correo + fecha de cada uso | `usage_carryover_events` | Evitar reiniciar la cuota con una baja | Hasta 31 días |
| HMAC del correo + consumo del periodo (sistema mensual anterior) | `usage_carryover` | Ya no se escribe; se sigue leyendo | Filas existentes, sin borrar |
| Eventos de seguridad con HMAC de IP | `security_events` | Detectar abuso | 90 días, **si se programa la purga** |
| HMAC de IP y de correo en contadores | Upstash | Límites de frecuencia | Minutos a 24 horas |
| URL analizada sin cuenta | En ningún sitio | — | No se guarda |

Los informes no contienen el HTML de la web analizada ni valores de cookies. Los datos de un análisis son técnicos (cabeceras, certificado, DNS); los personales son el correo, el nombre y, de forma seudonimizada, la IP.

### Lo que no se puede afirmar

No se afirma que el producto cumpla el RGPD. Faltan decisiones y textos que necesitan revisión profesional:

1. Aviso legal con el titular del servicio.
2. Política de privacidad: base jurídica, encargados (Supabase, Upstash, Resend, Vercel), transferencias internacionales y plazos.
3. Si el HMAC de IP y de correo se considera dato personal (es seudonimización, no anonimización: probablemente sí).
4. Condiciones de uso: analizar solo webs propias o autorizadas; «no es una certificación ni un pentest».
5. Política de cookies: hoy solo hay cookies técnicas de sesión.
6. Contacto de seguridad y de abuso, y `security.txt` propio.
7. Procedimiento para atender solicitudes de acceso, rectificación y supresión (la exportación y el borrado ya existen en el panel).
8. Región de los datos: elegir la UE en Supabase y Upstash.

## 10. Documentación

| Documento | Contenido |
|---|---|
| `SETUP_SUPABASE.md` | Supabase local y en la nube, paso a paso |
| `SECURITY_ACCOUNTS.md` | Autenticación, sesiones, roles, RLS, pruebas de aislamiento, riesgos |
| `PLANS_AND_QUOTAS.md` | Planes, consumo, periodos, abuso, cómo probar Pro |
| `ENVIRONMENT_VARIABLES.md` | Variables, entornos y dónde obtener cada valor |
| `STRIPE_NEXT_PHASE.md` | Facturación: lo preparado y lo pendiente |
| `TESTING_REPORT.md` | Qué se ha probado y cómo |
| `SCORING_MODEL.md`, `CHECK_CATALOG.md`, `CALIBRATION_REPORT.md`, `SECURITY_METHODOLOGY.md` | Motor (sin cambios en esta fase) |
| `ENGINE_DIAGNOSIS.md` | Histórico |
| `PRO_PRODUCT_SPEC.md`, `PRO_SERVICES.md`, `COST_ANALYSIS.md`, `ROADMAP.md` | Planificación anterior, parcialmente superada (llevan aviso) |
