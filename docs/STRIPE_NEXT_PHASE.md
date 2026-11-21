# STRIPE_NEXT_PHASE — Facturación (fase futura)

**Estado:** nada de Stripe está implementado, instalado ni configurado. No hay claves, productos, precios, rutas de pago ni webhooks. Este documento describe lo que ya está preparado y lo que habrá que construir. **No hay precios decididos.**

## 1. Lo que ya está preparado

| Pieza | Dónde | Estado |
|---|---|---|
| Planes y capacidades separados del proveedor de pagos | `lib/plans.ts` → `entitlementsFor(plan)` | En uso |
| Plan efectivo calculado en la base de datos | Función SQL `effective_plan` | En uso y probado |
| Tabla de suscripciones | `public.subscriptions` | Creada; hoy todas las filas son `free` / `provider = 'none'` |
| Periodo de consumo ligado al ciclo de facturación | Función SQL `usage_period` | Ya **no decide la cuota** (desde el 17-11-2026 la cuota es una ventana móvil de 7 días); solo rellena `period_start` por compatibilidad |
| Tabla de eventos de facturación procesados | `public.billing_webhook_events` (clave: proveedor + id de evento) | Creada, vacía |
| Tipos e interfaz del proveedor | `lib/billing/provider.ts` (`BillingProvider`, `SubscriptionChange`) | Solo tipos; sin implementación |
| Botón de contratación | Pestaña «Plan» del panel | **Desactivado**, con el texto «Pro · próximamente» |

Ninguna pantalla ni ruta consulta Stripe ni una suscripción directamente: preguntan qué permite el plan. Cuando Stripe exista, lo único que cambiará será quién escribe en `subscriptions`.

### Columnas de `subscriptions`

`workspace_id`, `plan` (`free` | `pro`), `status` (`active` | `trialing` | `past_due` | `canceled` | `incomplete`), `provider` (`none` | `manual` | `stripe`), `provider_customer_id`, `provider_subscription_id`, `current_period_start`, `current_period_end`, `cancel_at_period_end`, `created_at`, `updated_at`.

El usuario puede leer la suya; **no puede escribir** (verificado: `42501`). Solo el servidor, con la clave secreta, modifica esta tabla.

## 2. Principio de diseño

> Pro se activa cuando el servidor recibe y verifica un evento de Stripe, nunca porque el usuario vuelva a una página de «pago correcto».

La página de éxito solo mostrará «estamos confirmando tu pago» y consultará el plan hasta que el webhook lo haya actualizado.

## 3. Lo que habrá que construir

### 3.1 Contratación — Stripe Checkout

- Ruta de servidor `POST /api/billing/checkout`: exige sesión y mismo origen; crea una *Checkout Session* en modo suscripción con el precio de Pro, `client_reference_id = workspace_id` y el cliente de Stripe del espacio (creándolo si no existe y guardando `provider_customer_id`).
- El identificador del precio sale de configuración del servidor (`STRIPE_PRICE_PRO_MONTHLY` / `_YEARLY`), nunca de la petición.
- La ruta solo devuelve la URL de Stripe. Ningún dato de tarjeta pasa por WebTrustScan.

### 3.2 Gestión — Customer Portal

- Ruta `POST /api/billing/portal`: crea una sesión del portal para el `provider_customer_id` **del espacio del usuario autenticado** (nunca uno recibido en la petición) y devuelve la URL.
- Cancelar, cambiar de medio de pago y descargar facturas se hace en el portal de Stripe.

### 3.3 Webhooks

Ruta `POST /api/billing/webhook`, con estas reglas:

1. **Verificar la firma** con `STRIPE_WEBHOOK_SECRET` sobre el cuerpo **sin procesar** (antes de `JSON.parse`). Firma inválida → 400 y nada más. No se implementa ninguna ruta que acepte eventos sin verificar.
2. **Idempotencia:** insertar `(provider, event_id)` en `billing_webhook_events`; si ya existía, responder 200 sin hacer nada. Stripe reenvía eventos y puede entregarlos desordenados.
3. **Fuente de verdad:** ante un evento de suscripción, consultar a Stripe el estado actual de esa suscripción y volcarlo, en lugar de confiar en el orden de llegada.
4. **Actualizar `subscriptions`** en una transacción y registrar el cambio en `security_events`.
5. Responder 2xx en pocos segundos; cualquier trabajo largo, después.
6. La ruta queda fuera de la comprobación de mismo origen (la llama Stripe) y de la sesión; su única autenticación es la firma.

### Eventos a manejar

| Evento | Qué hacer |
|---|---|
| `checkout.session.completed` | Asociar el cliente y la suscripción de Stripe al espacio (`client_reference_id`). |
| `customer.subscription.created` | Crear o actualizar la fila: plan, estado y periodo. |
| `customer.subscription.updated` | Renovaciones, cambios de plan, `cancel_at_period_end`, paso a `past_due` o `active`. Actualiza el periodo: de él depende la cuota. |
| `customer.subscription.deleted` | Fin de la suscripción: `status = 'canceled'`. El plan efectivo vuelve a Free. |
| `invoice.paid` | Confirmar la renovación y el nuevo periodo. |
| `invoice.payment_failed` | Marcar `past_due`; avisar al usuario. Decidir cuántos días de gracia hay antes de volver a Free (hoy `past_due` equivale a Free de inmediato). |
| `charge.refunded` / `charge.dispute.created` | Registrar; decidir caso a caso si se retira Pro. |

### 3.4 Correspondencia de estados

| Estado en Stripe | `status` | Plan efectivo |
|---|---|---|
| `active` | `active` | Pro |
| `trialing` | `trialing` | Pro |
| `past_due`, `unpaid` | `past_due` | Free |
| `canceled`, `incomplete_expired` | `canceled` | Free |
| `incomplete` | `incomplete` | Free |

Con `cancel_at_period_end = true` la suscripción sigue `active` hasta el final del periodo: el usuario conserva Pro hasta entonces.

### 3.5 Cuota y ciclo de facturación

`usage_period` ya usa `current_period_start` / `current_period_end` cuando la suscripción es Pro y está vigente. Decisiones pendientes:

- La cuota es una ventana móvil de 7 días independiente del ciclo de facturación (ver `PLANS_AND_QUOTAS.md` §3). Al pasar de Free a Pro, los usos de los últimos 7 días siguen contando, ahora contra el límite de Pro (25).
- Al volver a Free con más de 5 usos en la ventana, no se podrá analizar hasta que bajen de 5; el panel indica la fecha.

## 4. Seguridad

- `STRIPE_SECRET_KEY` y `STRIPE_WEBHOOK_SECRET` solo en el servidor, sin prefijo `NEXT_PUBLIC_`, distintas en Preview (modo test) y producción.
- Usar claves **restringidas** de Stripe con los permisos mínimos.
- Nunca registrar el cuerpo completo de un evento ni datos de pago.
- El plan nunca se lee de la URL de retorno ni de un parámetro del cliente.
- Tests obligatorios antes de activar: firma inválida, evento repetido, eventos desordenados, cancelación, pago fallido, un usuario intentando abrir el portal de otro espacio.

## 5. Tareas para activar pagos, en orden

1. Decidir precios y periodicidad, y qué diferencia a Pro además de los límites.
2. Resolver la parte fiscal (IVA en la UE) y redactar condiciones de contratación, desistimiento y reembolsos.
3. Crear la cuenta de Stripe y, **en modo test**, el producto Pro y sus precios.
4. Añadir la dependencia `stripe` e implementar `BillingProvider` y las tres rutas.
5. Probar todo el ciclo en modo test con las tarjetas de prueba de Stripe y la CLI de Stripe para reenviar webhooks.
6. Configurar el Customer Portal en el panel de Stripe.
7. Activar el botón de la pestaña «Plan».
8. Solo entonces, claves reales en producción.

Documentación oficial a consultar en ese momento (las API cambian): <https://docs.stripe.com/billing/subscriptions>, <https://docs.stripe.com/webhooks>, <https://docs.stripe.com/keys>.
