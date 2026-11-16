# PLANS_AND_QUOTAS — Planes, cuotas y prevención de abuso

**Actualizado:** 16 de noviembre de 2026. Los valores son **técnicos y provisionales**, para poder probar. No son precios ni una decisión comercial.

## 1. Dónde se configura

Un único fichero: [`lib/plans.ts`](../lib/plans.ts). Ninguna página ni ruta repite un límite.

| Característica | Visitante sin cuenta | Free | Pro |
|---|---:|---:|---:|
| Análisis | 2 al día por IP | 5 por periodo | 100 por periodo |
| Historial guardado | — | 10 últimos | 100 últimos |
| Análisis simultáneos | 1 | 2 | 2 |
| Informe completo, PDF e impresión | Sí | Sí | Sí |
| Prioridad, equipos | No | No | No |

No se ha inventado ninguna función Pro que no exista: hoy Pro solo cambia dos números.

## 2. Cómo se determina el plan

1. El plan está en `subscriptions.plan`. **El usuario no tiene permiso de escritura** sobre esa tabla (permiso denegado por PostgreSQL, no por el código).
2. El **plan efectivo** lo calcula la base de datos (`effective_plan`): Pro solo si la suscripción está `active` o `trialing`; en cualquier otro estado, Free.
3. La aplicación convierte ese plan en capacidades con `entitlementsFor()`. Ninguna pantalla consulta la suscripción ni un proveedor de pagos. Un valor desconocido se trata como Free.

Nada de lo que envíe el navegador interviene: probado enviando `plan`, `limit`, `used`, `userId` y `workspaceId` en la petición.

## 3. Cómo se consume un análisis

El consumo es un registro del servidor (`usage_events`), no un contador ni una lista de dominios.

```
POST /api/analyze {url, requestId}
  1. ¿Hay control de abuso?            no → 503
  2. Límite por minuto del analizador  superado → 429
  3. Validar la URL y el destino       inválida → 400   (no consume)
  4. Con sesión:
       reserve_audit()  ── una sola transacción, con la fila de la suscripción bloqueada:
         · ¿requestId ya visto?        → se devuelve el análisis ya hecho (no consume)
         · ¿cuota agotada?             → 429
         · ¿demasiados en curso?       → 429
         · inserta el consumo «reserved»
       ejecutar el motor
         · informe                     → complete_audit(): guarda y marca «completed»
         · el destino falla            → «failed»   (cuenta)
         · error interno nuestro       → «released» (no cuenta)
     Sin sesión:
       plaza de concurrencia + límite diario por IP, y ejecutar el motor
```

### Cuándo se descuenta

| Situación | ¿Consume? |
|---|---|
| URL mal escrita, IP interna, puerto no permitido | No (se rechaza antes) |
| Análisis completado | Sí |
| El destino no responde, no existe o agota el tiempo | **Sí.** El servidor hizo el trabajo; si no contara, reintentar contra un dominio caído sería gratis |
| Error interno del servicio | No: se devuelve |
| Reintento con el mismo `requestId` | No: devuelve el mismo informe |

### Qué no reinicia el contador

| Intento | Resultado | Prueba |
|---|---|---|
| Borrar análisis del historial (o todo el historial) | El consumo permanece | BD y aplicación |
| Repetir la petición o reintentar tras un error de red | Un solo consumo por `requestId` | BD y aplicación |
| Veinte peticiones simultáneas | Exactamente 5 aceptadas | BD |
| Cambiar parámetros desde DevTools | Se ignoran | Aplicación |
| Reintentar tras errores | Cuentan | Aplicación |
| Darse de baja y registrarse con el mismo correo | El consumo del periodo se arrastra | BD y aplicación |
| Lanzar análisis desde otra web con la sesión del usuario | Se tratan como anónimos | Aplicación |

La atomicidad la da PostgreSQL: `reserve_audit` bloquea la fila de la suscripción (`select … for update`), así que dos reservas del mismo espacio se ejecutan una tras otra. **Limitación de la prueba:** se ha comprobado con peticiones simultáneas sobre una sola conexión; con varias conexiones reales depende de ese bloqueo, que es el mecanismo estándar pero no se ha ejecutado contra Supabase.

## 4. Periodos

- **Free:** mes natural en UTC. El contador se reinicia el día 1 a las 00:00 UTC. Probado en el cambio de mes (23:59:59 → 00:00:00) y con una hora expresada en horario de Madrid.
- **Pro:** si la suscripción tiene un ciclo de facturación vigente (`current_period_start` / `current_period_end`), el periodo es ese ciclo; si no, el mes natural UTC. Así, cuando llegue Stripe, bastará con que el webhook rellene esas dos fechas.

## 5. Visitantes sin cuenta

El analizador público sigue funcionando sin registro, con su propio límite: **2 análisis al día por IP**, uno a la vez, además de los 10 por minuto por cliente y 120 por minuto globales. Es independiente de las cuotas de las cuentas.

- La IP es la que aporta la plataforma, no una cabecera del cliente.
- Se guarda un HMAC de la IP, no la IP.
- Sin *fingerprinting* ni identificadores del navegador.
- Fuera de Vercel y sin `TRUSTED_PROXY_HOPS`, la aplicación no puede fiarse de ninguna IP y **todos los visitantes comparten el mismo cupo**.

## 6. Abuso mediante cuentas múltiples

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

Con lo actual, quien disponga de muchas direcciones de correo reales puede obtener 5 análisis por cada una, a un ritmo de 5 altas por hora e IP. Es un coste aceptable para una beta; el CAPTCHA es el siguiente paso si se observa abuso.

## 7. Probar Pro sin pagos

No existe ninguna ruta de la aplicación que cambie un plan.

**En local:** abre Supabase Studio (<http://127.0.0.1:54323>) → **SQL Editor**, pega [`supabase/dev/set-plan.sql`](../supabase/dev/set-plan.sql), cambia el correo y ejecútalo. Para volver a Free, cambia `'pro'` por `'free'`.

**En los tests:** las pruebas asignan el plan con una sentencia SQL directa.

**En producción:** hasta que exista Stripe, todas las cuentas se crean y permanecen en Free (lo impone el disparador `handle_new_user` y la falta de permisos de escritura). Solo quien tenga acceso al panel de Supabase puede cambiar un plan a mano; hacerlo deja `provider = 'manual'` como rastro.

## 8. Cambiar un límite

Edita `lib/plans.ts` y despliega. No hay que tocar la base de datos: las funciones SQL reciben los límites en cada llamada. Un cambio se aplica a todas las cuentas en el periodo en curso.
