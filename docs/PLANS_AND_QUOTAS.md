# PLANS_AND_QUOTAS — Planes, cuotas y prevención de abuso

**Actualizado:** 17 de noviembre de 2026. Los valores son **técnicos y provisionales**, para poder probar. No son precios ni una decisión comercial.

## 1. Dónde se configura

Un único fichero: [`lib/plans.ts`](../lib/plans.ts). Ninguna página ni ruta repite un límite.

| Característica | Visitante sin cuenta | Free | Pro |
|---|---:|---:|---:|
| Análisis | 2 al día por IP | **5 cada 7 días** | **25 cada 7 días** |
| Historial guardado | — | 10 últimos | 50 últimos |
| Análisis simultáneos | 1 | 2 | 2 |
| Informe completo, PDF e impresión | Sí | Sí | Sí |
| Prioridad, equipos | No | No | No |

No se ha inventado ninguna función Pro que no exista: hoy Pro solo cambia dos números.

## 2. Cómo se determina el plan

1. El plan está en `subscriptions.plan`. **El usuario no tiene permiso de escritura** sobre esa tabla (permiso denegado por PostgreSQL, no por el código).
2. El **plan efectivo** lo calcula la base de datos (`effective_plan`): Pro solo si la suscripción está `active` o `trialing`; en cualquier otro estado, Free.
3. La aplicación convierte ese plan en capacidades con `entitlementsFor()`. Ninguna pantalla consulta la suscripción ni un proveedor de pagos. Un valor desconocido se trata como Free.

Nada de lo que envíe el navegador interviene: probado enviando `plan`, `limit`, `used`, `userId` y `workspaceId` en la petición.

## 3. Ventana móvil de 7 días

**Cada análisis consumido cuenta durante los 7 días siguientes al momento en que se hizo y después se libera.** No hay un día de reinicio: en cualquier intervalo de 7 días una cuenta Free hace como máximo 5 análisis.

- Las fechas son instantes absolutos (`timestamptz`) y se comparan en el servidor. El servidor responde siempre en UTC (ISO 8601); el panel las muestra en la zona horaria del navegador, indicándola (por ejemplo «19 de noviembre de 2026, 18:05 CET»).
- Un uso hecho a las 09:00 UTC del día 10 deja de contar exactamente a las 09:00 UTC del día 17 (probado al milisegundo).
- El panel muestra «3 de 5 análisis utilizados en los últimos 7 días», cuándo se libera el siguiente uso y, si no queda ninguno, desde cuándo se podrá hacer otro.
- Si una cuenta tiene más usos que su límite (por ejemplo al pasar de Pro a Free), la fecha disponible es la del uso que hace bajar el consumo por debajo del límite, no la del más antiguo.
- La ventana (`QUOTA_WINDOW_DAYS = 7`) y los límites salen de `lib/plans.ts`; la base de datos solo admite ventanas de 1 a 31 días.

## 4. Cómo se consume un análisis

El consumo es un registro del servidor (`usage_events`), independiente del historial: no es un contador ni una lista de dominios.

```
POST /api/analyze {url, requestId}
  1. ¿Hay control de abuso?            no → 503
  2. Límite por minuto del analizador  superado → 429
  3. Validar la URL y el destino       inválida → 400   (no consume)
  4. Con sesión:
       reserve_audit_rolling()  ── una sola transacción, con la fila de la suscripción bloqueada:
         · ¿requestId ya visto?        → se devuelve el análisis ya hecho (no consume)
         · ¿7 días con el cupo lleno?  → 429, con la fecha (UTC) en que habrá uno libre
         · ¿demasiados en curso?       → 429
         · inserta el consumo «reserved»
       ejecutar el motor
         · informe                     → complete_audit(): guarda, marca «completed» y recorta el historial
         · el destino falla            → «failed»   (cuenta)
         · error interno nuestro       → «released» (no cuenta)
     Sin sesión:
       plaza de concurrencia + límite diario por IP, y ejecutar el motor
```

### Cuándo se descuenta

| Situación | ¿Consume? |
|---|---|
| URL mal escrita, IP interna, puerto no permitido | No (se rechaza antes) |
| Análisis completado | Sí, durante 7 días |
| El destino no responde, no existe o agota el tiempo | **Sí, durante 7 días.** El servidor hizo el trabajo; si no contara, reintentar contra un dominio caído sería gratis |
| Error interno del servicio | No: se devuelve |
| Reintento con el mismo `requestId` | No: devuelve el mismo informe |

### Qué no reinicia el contador

| Intento | Resultado | Prueba |
|---|---|---|
| Borrar análisis del historial (o todo el historial) | El consumo permanece | BD y aplicación |
| Repetir la petición o reintentar tras un error de red | Un solo consumo por `requestId` | BD y aplicación |
| Doce peticiones simultáneas | Exactamente 5 aceptadas | BD |
| Cambiar parámetros desde DevTools | Se ignoran | Aplicación |
| Reintentar tras errores | Cuentan | Aplicación |
| Darse de baja y registrarse con el mismo correo | Cada uso sigue contando hasta su fecha de liberación | BD y aplicación |
| Lanzar análisis desde otra web con la sesión del usuario | Se tratan como anónimos | Aplicación |

La atomicidad la da PostgreSQL: `reserve_audit_rolling` bloquea la fila de la suscripción (`select … for update`), así que dos reservas del mismo espacio se ejecutan una tras otra. **Limitación de la prueba:** se ha comprobado con peticiones simultáneas sobre una sola conexión (PostgreSQL embebido); con varias conexiones reales depende de ese bloqueo, que es el mecanismo estándar pero no se ha ejecutado contra Supabase.

## 5. Historial

- Free conserva los **10** análisis más recientes y Pro los **50**.
- El recorte lo hace `complete_audit` **solo al guardar un análisis nuevo**: borra del historial los que excedan el límite del plan, del más antiguo al más reciente. Borrar del historial no devuelve usos (el consumo está en `usage_events`).
- La migración del 17-11-2026 **no borra nada**.

### Transición del cambio de límites (Pro: de 100 a 50)

Free no cambia (10). Para Pro, un espacio que hoy tenga más de 50 análisis guardados los conservará todos **hasta su siguiente análisis**; en ese momento quedarán los 50 más recientes y se borrarán los demás de forma definitiva.

Hoy Pro solo se asigna a mano (no hay pagos), así que es muy probable que ninguna cuenta esté afectada. Antes de desplegar, compruébalo en el **SQL Editor** de Supabase (solo lectura):

```sql
select a.workspace_id, count(*) as guardados
from public.audits a
join public.subscriptions s on s.workspace_id = a.workspace_id
where s.plan = 'pro'
group by a.workspace_id
having count(*) > 50;
```

Si devuelve filas, hay que decidir antes de desplegar: avisar a esas cuentas, exportar sus datos o mantener temporalmente un límite mayor. No se ha tomado esa decisión en el código.

## 6. Paso del sistema mensual al de 7 días

La migración `20261117020000_rolling_quota.sql`:

- **No modifica ni borra filas.** El consumo ya registrado cuenta por su fecha real (`usage_events.created_at`): un análisis hecho hace 3 días sigue contando 4 días más.
- **No modifica las funciones anteriores** (`workspace_usage`, `reserve_audit`, `record_account_deletion`). La versión desplegada sigue funcionando con ellas hasta que se publique el código nuevo.
- Añade `workspace_usage_rolling`, `reserve_audit_rolling`, `record_account_deletion_rolling`, `rolling_usage` y `quota_window`, solo ejecutables por `service_role`.
- Añade la tabla `usage_carryover_events` (fecha de cada uso arrastrado tras una baja, bajo un HMAC del correo), con RLS y sin políticas. Los arrastres antiguos de `usage_carryover` se siguen leyendo: cuentan 7 días desde la baja.
- Los nuevos consumos siguen rellenando `period_start` (mes UTC), de modo que volver a la versión anterior no rompe nada.
- Añade un índice `(workspace_id, created_at)` sobre `usage_events`.

**Orden obligatorio:** 1) aplicar la migración, 2) desplegar el código. Al revés, el código nuevo llamaría a funciones que aún no existen y los análisis con cuenta fallarían.

Al activar la ventana, alguien que hubiera agotado el cupo mensual a principios de mes puede volver a tener análisis disponibles (los de hace más de 7 días se liberan). Es el comportamiento pedido.

## 7. Visitantes sin cuenta

El analizador público sigue funcionando sin registro, con su propio límite: **2 análisis al día por IP**, uno a la vez, además de los 10 por minuto por cliente y 120 por minuto globales. Es independiente de las cuotas de las cuentas.

- La IP es la que aporta la plataforma, no una cabecera del cliente.
- Se guarda un HMAC de la IP, no la IP.
- Sin *fingerprinting* ni identificadores del navegador.
- Fuera de Vercel y sin `TRUSTED_PROXY_HOPS`, la aplicación no puede fiarse de ninguna IP y **todos los visitantes comparten el mismo cupo**.

## 8. Abuso mediante cuentas múltiples

Ningún sistema impide del todo que alguien cree otra cuenta. Lo que hay:

| Barrera | Estado |
|---|---|
| Correo verificado obligatorio | Implementado |
| Altas limitadas por IP (5 por hora) | Implementado |
| Accesos y recuperaciones limitados por IP y por cuenta | Implementado |
| Cuota por espacio, reservada de forma atómica | Implementado |
| Concurrencia limitada | Implementado |
| Idempotencia de peticiones | Implementado |
| La baja no reinicia la cuota del mismo correo | Implementado |
| Registro de señales (altas y accesos fallidos por IP anonimizada) | Implementado |
| CAPTCHA | **No implementado** (ver `SECURITY_ACCOUNTS.md` §2) |
| Bloqueo de correos desechables o alias (`nombre+1@`) | **No implementado** |

Con lo actual, quien disponga de muchas direcciones de correo reales puede obtener 5 análisis por semana por cada una, a un ritmo de 5 altas por hora e IP. Es un coste aceptable para una beta; el CAPTCHA es el siguiente paso si se observa abuso.

## 9. Probar Pro sin pagos

No existe ninguna ruta de la aplicación que cambie un plan.

**En local:** abre Supabase Studio (<http://127.0.0.1:54323>) → **SQL Editor**, pega [`supabase/dev/set-plan.sql`](../supabase/dev/set-plan.sql), cambia el correo y ejecútalo. Para volver a Free, cambia `'pro'` por `'free'`.

**En los tests:** las pruebas asignan el plan con una sentencia SQL directa.

**En producción:** hasta que exista Stripe, todas las cuentas se crean y permanecen en Free (lo impone el disparador `handle_new_user` y la falta de permisos de escritura). Solo quien tenga acceso al panel de Supabase puede cambiar un plan a mano; hacerlo deja `provider = 'manual'` como rastro.

## 10. Cambiar un límite

Edita `lib/plans.ts` y despliega. No hay que tocar la base de datos: las funciones SQL reciben los límites y la ventana en cada llamada. Un cambio se aplica de inmediato a todas las cuentas, contando los usos ya registrados en la ventana. Si baja `historySize`, revisa antes la §5: el recorte se aplica en el siguiente análisis de cada cuenta.
