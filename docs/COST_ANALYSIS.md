# COST_ANALYSIS — Infraestructura y costes

> **DOCUMENTO DE PLANIFICACIÓN, PARCIALMENTE SUPERADO (16-11-2026).** Recoge análisis previos a la arquitectura actual. Lo que diga sobre autenticación propia, PGlite, Neon, dominios guardados u organizaciones **ya no es cierto**: hoy las cuentas usan Supabase Auth y PostgreSQL con RLS, los planes son Free y Pro, y no hay pagos. Estado real: `HANDOFF.md`, `SECURITY_ACCOUNTS.md`, `PLANS_AND_QUOTAS.md` y `STRIPE_NEXT_PHASE.md`.

**Aviso:** las cifras de proveedores proceden de búsquedas hechas el 15 de noviembre de 2026, en parte de fuentes secundarias. Están marcadas con su fuente; **confírmalas en la página oficial antes de decidir**. No se ha contratado ni configurado nada.

## 1. Qué consume un análisis

| Recurso | Motor 1.x | Engine 2.0 |
|---|---|---|
| Invocaciones de función | 1 | 1 |
| Peticiones HTTP salientes | 2 (en serie) | Hasta 5 (1 + 4 en paralelo) + 1 saludo TLS |
| Consultas DNS | 0 | ~4–10 (MX, TXT, CAA, con herencia) |
| Datos recibidos | Solo cabeceras | Hasta 512 KB de HTML + 16 KB |
| Duración máxima | 20 s (tope propio), 30 s (`maxDuration`) | Igual |
| Respuesta al cliente | ~1 KB | ~15 KB de JSON |
| Almacenamiento | Ninguno | Ninguno (Pro: ~15 KB por auditoría guardada) |

El coste dominante en serverless es el **tiempo de función**, y casi todo es espera de red. La duración real depende de la latencia del sitio analizado; **no se ha medido en Vercel**. El peor caso está acotado a 20 s por diseño.

Con el límite global actual (120 análisis/minuto) el techo teórico es de 172.800 análisis al día. Ese tope protege a terceros, no a tu factura: **conviene bajarlo** mientras no haya ingresos (por ejemplo 20–30/minuto) mediante `RATE_LIMIT_GLOBAL_PER_MINUTE`.

## 2. Vercel

| Dato | Valor | Fuente |
|---|---|---|
| Plan Hobby | Gratuito, **solo uso personal no comercial**. Cobrar, anunciar un producto o servicio, o mostrar publicidad cuenta como uso comercial. | Directrices de uso razonable de Vercel, citadas por [convika.com](https://convika.com/compare/vercel-hobby-commercial-use/) y [zplatform.ai](https://zplatform.ai/guides/is-vercel-free/) |
| Plan Pro | 20 $/mes por puesto, con 20 $ de crédito de uso incluido | [massivegrid.com](https://massivegrid.com/blog/vercel-pricing-explained-2026/), [stork.ai](https://www.stork.ai/blog/vercel-pricing-2026) |
| Hobby: al superar un límite | Las funciones se pausan (no se factura exceso) | Ídem |
| Duración máxima de función por plan | **No confirmada** en esta búsqueda | Comprobar en la documentación de límites de Vercel |

Consecuencias:

- **Mientras WebTrustScan sea gratuito y sin publicidad, Hobby es defendible. En cuanto anuncies planes de pago o cobres, necesitas Pro.** Es el primer coste fijo del negocio (20 $/mes) y hay que contarlo en el precio.
- El código declara `maxDuration = 30`. Hay que confirmar que tu plan lo admite; si el límite fuera menor, la plataforma cortaría la función antes que el propio motor (que para a los 20 s).
- El renderizado dinámico por los *nonces* de la CSP hace que cada visita a la portada invoque una función. Con poco tráfico es irrelevante. Si creciera, la alternativa es CSP con *hashes* y página estática (más trabajo de mantenimiento en cada despliegue).

## 3. Límite de peticiones: Upstash frente a Vercel WAF

El problema: en serverless cada instancia tiene su memoria, así que el contador en memoria no es compartido. Las auditorías dejaron preparada la integración con Upstash.

| Opción | Qué ofrece | Coste | Encaje |
|---|---|---|---|
| **Memoria (actual)** | Límite por instancia | 0 | Insuficiente como única barrera en producción |
| **Vercel WAF · regla de *rate limit*** | Límite en el borde, antes de invocar la función | Hobby: 1 regla por proyecto y 1 M de peticiones permitidas incluidas. Pro: 40 reglas, ~0,50 $ por millón de peticiones permitidas. ([documentación de Vercel](https://vercel.com/docs/vercel-firewall/vercel-waf/rate-limiting), [precios](https://vercel.com/docs/vercel-firewall/vercel-waf/usage-and-pricing)) | **Mejor primera línea**: el tráfico bloqueado no llega a ejecutar código ni a generar peticiones salientes |
| **Upstash Redis** | Contador compartido exacto, con lógica propia (por cliente y global) | Gratis hasta ~500.000 comandos/mes; después ~0,20 $ por 100.000 comandos ([aibizhub.io](https://aibizhub.io/articles/upstash-pricing/), [blog de Upstash](https://upstash.com/blog/upstash-vs-aws-elasticache-serverless-redis-pricing-and-performance-2026)) | Necesario solo si quieres el límite **global** exacto o cuotas por plan |

**Recomendación:**

1. **Ahora:** crear una regla de *rate limit* del WAF de Vercel para `POST /api/analyze` por IP (por ejemplo 10 por minuto). Una sola regla cabe en Hobby, no cuesta nada y cierra el hueco principal. Es un cambio en tu cuenta de Vercel: **requiere tu autorización y lo tienes que hacer tú**.
2. **Mantener** el limitador en memoria como segunda capa (ya está).
3. **Upstash solo cuando llegue Pro**, porque entonces hará falta un almacén compartido para cuotas por organización. En ese momento, si ya hay PostgreSQL, valora llevar las cuotas a la base de datos y ahorrarte un proveedor.

Estimación de Upstash si se activara hoy: cada análisis consume un puñado de comandos (los contadores por cliente y global). Con el plan gratuito de ~500.000 comandos/mes caben del orden de 100.000 análisis mensuales, muy por encima de un tráfico inicial. El número exacto de comandos por análisis no lo he medido.

## 4. Coste de WebTrustScan Pro

Costes fijos previsibles al lanzar Pro (todos por confirmar):

| Concepto | Coste | Nota |
|---|---|---|
| Vercel Pro | 20 $/mes | Obligatorio para uso comercial |
| Dominio | El que ya tengas | — |
| PostgreSQL serverless | Plan gratuito al inicio | Los informes son pequeños (~15 KB) |
| Correo transaccional | Plan gratuito al inicio | Alertas y enlaces de acceso |
| Stripe | Sin cuota fija; comisión por transacción | Comisión exacta según país y método |

**El coste variable es la monitorización.** Cada dominio monitorizado a diario son ~30 ejecuciones del motor al mes (más la segunda ejecución de confirmación cuando hay una regresión). El tiempo de función por ejecución es el dato que falta medir en Vercel para convertirlo en dinero. Hasta tenerlo:

- Diseña los límites de plan en **número de dominios × frecuencia**, que es exactamente lo que genera coste.
- Ofrece diaria solo en planes de pago y semanal por defecto.
- Ejecuta la monitorización en una cola con concurrencia limitada, no en ráfaga.

**Informes PDF:** generarlos en el navegador del usuario cuesta 0. Generarlos en servidor con Chromium es la operación más cara y lenta que tendría el producto; aplázalo hasta que haya demanda de informes programados.

## 5. Sostenibilidad para un desarrollador independiente

- **Hoy:** coste 0 en Hobby, siempre que el servicio siga siendo no comercial.
- **Umbral de rentabilidad de Pro:** los costes fijos estimados (del orden de 20 $/mes) se cubren con muy pocas suscripciones a cualquier precio de mercado razonable. El riesgo económico no es la infraestructura sino el **tiempo de desarrollo y soporte**.
- **Riesgo de coste abusivo:** un atacante que dispare análisis no puede alargar cada uno más de 20 s, pero sí multiplicarlos. Las defensas, por orden: regla WAF, límite por cliente, límite global bajo y **alertas de gasto en Vercel** (configúralas; hoy no hay ninguna monitorización operativa).

## 6. Mediciones pendientes

Para sustituir estas estimaciones por datos:

1. Duración media y percentil 95 de `/api/analyze` en Vercel sobre 20–30 dominios propios o autorizados.
2. Comandos de Upstash por análisis (si se activa).
3. Límite real de `maxDuration` en tu plan.
4. Si la sonda de TLS 1.0–1.1 funciona en el runtime de Vercel o devuelve «no comprobable».
