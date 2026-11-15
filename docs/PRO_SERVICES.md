# PRO_SERVICES — Servicios externos: opciones, costes y decisiones pendientes

**Fecha:** 15 de noviembre de 2026. Las cifras proceden en su mayoría de comparativas de terceros; están enlazadas y **deben confirmarse en la página oficial de cada proveedor**. No se ha contratado, configurado ni dado de alta nada.

## Qué funciona hoy sin ningún servicio

La primera fase de Pro (cuentas, organizaciones, dominios, verificación, auditorías guardadas, historial y comparación) funciona en local con PostgreSQL embebido (PGlite). Para ponerla en producción solo falta **una** decisión: la base de datos.

## 1. Base de datos PostgreSQL — necesaria para publicar la fase 1

El código usa SQL estándar a través de `pg`, así que sirve cualquier PostgreSQL. Solo hay que definir `DATABASE_URL`.

| Opción | Plan gratuito (según fuentes) | De pago | Observaciones |
|---|---|---|---|
| **Neon** | ~1 GB por proyecto, ~100 horas de cómputo al mes, se suspende cuando no hay uso | Por uso: ~0,106 $ por hora de cómputo y ~0,35 $ por GB-mes, sin mínimo | Escala a cero: encaja con poco tráfico. Las cifras del plan gratuito varían entre fuentes. |
| **Supabase** | 500 MB; **el proyecto se pausa tras una semana sin actividad** | Pro desde 25 $/mes | La pausa por inactividad es un riesgo real para un producto con poco uso inicial. Incluye autenticación propia que no necesitamos. |
| PostgreSQL propio (VPS) | — | Coste del servidor | Más control y más mantenimiento (copias, parches). No lo recomiendo ahora. |

**Recomendación: Neon, plan gratuito.** Un informe ocupa ~15 KB: 1 GB da para decenas de miles de auditorías. Usa su cadena de conexión *pooled* (la aplicación abre como mucho 3 conexiones por instancia).

**Lo que tendrías que hacer tú:** crear la cuenta y el proyecto, y añadir `DATABASE_URL` a las variables de entorno de Vercel (Preview primero). Las migraciones se aplican solas.

Fuentes: [Neon vs Supabase, plan gratuito](https://neon.com/guides/neon-vs-supabase-free-plan) · [jetadmin](https://www.jetadmin.io/blog/neon-vs-supabase/) · [draxlr](https://www.draxlr.com/blogs/supabase-vs-neon/)

## 2. Correo transaccional — necesario para la fase 2 (alertas) y para verificar correos

Hoy el registro no verifica la dirección de correo ni permite recuperar la contraseña, porque ambas cosas exigen enviar correo.

| Opción | Gratis | De pago | Observaciones |
|---|---|---|---|
| **Resend** | ~3.000 correos/mes, 100/día | ~20 $/mes por 50.000 | API sencilla. El límite diario de 100 basta para empezar. |
| **Postmark** | 100 correos/mes | ~15 $/mes por 10.000 | Muy buena entregabilidad; el gratuito se queda corto. |
| **Amazon SES** | Sin plan gratuito estándar para cuentas nuevas | ~0,10–0,16 $ por 1.000 | El más barato a volumen; hay que gestionar rebotes y quejas a mano. |

**Recomendación: Resend, plan gratuito**, con el envío aislado detrás de una interfaz para poder cambiar de proveedor. Requiere además verificar tu dominio de envío con registros DNS (SPF/DKIM), que es un **cambio de DNS: necesita tu autorización**.

Fuentes: [thetechhacker](https://thetechhacker.com/2026/11/14/best-transactional-email-api/) · [buildmvpfast](https://www.buildmvpfast.com/api-costs/email) · [devtoolreviews](https://www.devtoolreviews.com/reviews/resend-vs-postmark-vs-amazon-ses-vs-sendgrid-2026)

## 3. Tareas programadas — necesarias para la monitorización (fase 2)

| Opción | Coste | Límite relevante |
|---|---|---|
| **Vercel Cron en Hobby** | 0 | **Una ejecución al día como máximo**, sin hora exacta garantizada ([documentación de Vercel](https://vercel.com/docs/cron-jobs/manage-cron-jobs)) |
| **Vercel Cron en Pro** | Incluido en los 20 $/mes | Frecuencias mayores (según guías de terceros) |
| Programador externo (GitHub Actions, cron-job.org, QStash) | 0 al inicio | Otro servicio que mantener y asegurar |

**Recomendación:** una única tarea diaria de Vercel Cron que reparte el trabajo: procesa por lotes los dominios cuya auditoría toca, con concurrencia limitada. Una ejecución al día **cabe en Hobby** y es suficiente para monitorización semanal o diaria. La restricción real no es técnica: Hobby no admite uso comercial, así que al cobrar habrá que pasar a Pro de todos modos.

## 4. Pagos — fase 4

| Opción | Comisión (según fuentes) | Observaciones |
|---|---|---|
| **Stripe** | Tarjetas del EEE: 1,5 % + 0,25 € (estándar) y 2,8 % + 0,25 € (premium); fuera del EEE, más ([precios de Stripe España](https://stripe.com/en-es/pricing)). Stripe Billing añade un porcentaje sobre el volumen de suscripciones que **no he podido confirmar para España**. | Tú eres el vendedor: te toca gestionar el IVA de cada país (OSS). |
| **Paddle / Lemon Squeezy** | Comisión mayor (no investigada en detalle) | Actúan como vendedor oficial (*merchant of record*) y liquidan ellos el IVA. Menos trabajo fiscal. |

**Recomendación:** Stripe, como pediste, siempre en modo test hasta validar toda la experiencia. Antes de activar cobros reales conviene que un asesor te confirme el tratamiento del IVA; si resulta pesado, Paddle es la alternativa.

**Lo que tendrías que hacer tú:** crear la cuenta de Stripe y darme las claves **de test** (`sk_test_…`, `whsec_…`) como variables de entorno locales. Nunca claves reales.

## 5. Alojamiento

Sin cambios respecto a `COST_ANALYSIS.md`: Hobby mientras el servicio no sea comercial; **Vercel Pro (20 $/mes) en cuanto se anuncien o cobren planes**.

## Resumen de costes

| Momento | Coste mensual estimado |
|---|---|
| Hoy (analizador público) | 0 |
| Fase 1 publicada (Neon gratuito) | 0 |
| Fase 2 (Resend gratuito, cron diario) | 0 |
| Al empezar a cobrar | ~20 $ (Vercel Pro) + comisiones de Stripe por venta |

## Decisiones que necesito de ti

1. **Base de datos:** ¿Neon? (crear cuenta y pasarme la variable en Preview).
2. **Correo:** ¿Resend? Y qué dominio de envío usar (implica registros DNS).
3. **Monitorización sin verificar el dominio:** propongo exigir verificación siempre, para que el servicio no pueda usarse para vigilar webs ajenas.
4. **Stripe:** cuenta y claves de test cuando quieras empezar la fase 4.
5. **Precios** de Pro y Agency: siguen sin fijar.
