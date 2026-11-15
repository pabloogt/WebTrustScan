# PRO_PRODUCT_SPEC — WebTrustScan Pro

**Estado:** especificación. En esta fase solo se ha construido lo que no necesita cuentas ni base de datos: el motor, el informe con vistas ejecutiva y técnica, la exportación a JSON y la impresión a PDF desde el navegador. Todo lo demás requiere decisiones tuyas (servicios, coste, legal) y está marcado como tal.

## 1. Posicionamiento

**Para quién:** desarrolladores y pequeñas agencias que mantienen varias webs y necesitan saber, sin ser especialistas en seguridad, si su configuración es correcta y cuándo deja de serlo.

**Qué no es:** un escáner de vulnerabilidades. Ese mercado tiene herramientas maduras y mucho más caras (ver §8) y competir ahí exigiría un motor de explotación que no queremos construir.

**En qué compite:**

1. **Puntuaciones que se pueden defender ante un cliente.** Cada punto perdido tiene evidencia; lo no aplicable no cuenta; lo no comprobado se dice.
2. **Honestidad sobre el alcance.** El informe distingue «tu web falla» de «no he podido verla». Ningún competidor gratuito que conozca separa cobertura de puntuación; es una afirmación que conviene verificar con una revisión de mercado antes de usarla en marketing.
3. **Monitorización de cambios**, no de vulnerabilidades: «tu HSTS ha desaparecido tras el despliegue del martes», «tu certificado caduca en 10 días».
4. **Informes para terceros:** la agencia entrega un PDF con su marca.

## 2. Decisiones de producto (y por qué)

| Decisión | Motivo |
|---|---|
| **Empezar por monitorización + historial, no por «más checks»** | Es lo único que justifica un pago recurrente. Un análisis puntual gratuito no retiene. |
| **Verificación de dominio antes que cualquier análisis profundo** | Requisito ético y legal para sondear rutas sensibles; además es la base del modelo de datos (un dominio verificado pertenece a una organización). |
| **Multi-organización desde el primer esquema**, aunque Agency llegue después | Añadir aislamiento entre clientes a posteriori es la fuente clásica de fugas de datos. |
| **PDF en el navegador ahora; PDF en servidor más adelante** | El PDF de servidor (Chromium *headless*) es caro en serverless. `window.print()` cubre el informe manual; el de servidor solo hace falta para informes programados por correo. |
| **No construir API pública todavía** | Sin usuarios que la pidan es superficie de ataque y de soporte. El JSON exportable cubre la integración manual. |
| **Descartar gestión de tareas / remediaciones** | Las agencias ya tienen su gestor. Mejor exportar (CSV/JSON, más adelante *webhook*) que competir con Jira. |

## 3. Evaluación de funcionalidades

Escala 1–5. *Coste* y *complejidad*: 5 = caro / difícil.

| Funcionalidad | Problema que resuelve | Usuarios | Diferencial | Fiabilidad | Complejidad | Coste infra | Mantenimiento | Riesgo seguridad | Potencial comercial | Decisión |
|---|---|---|---|---|---|---|---|---|---|---|
| Historial de auditorías | «¿He mejorado?» | Todos | 3 | 5 | 2 | 1 | 1 | Bajo | 4 | **Fase 1** |
| Comparación entre dos auditorías | Ver qué cambió | Todos | 4 | 5 | 2 | 1 | 1 | Bajo | 4 | **Fase 1** |
| Monitorización programada + alertas de cambio | Enterarse de regresiones | Pro, Agency | 5 | 4 | 3 | 2 | 3 | Medio (abuso de cron) | 5 | **Fase 1** |
| Aviso de caducidad de certificado | Evitar caídas | Todos | 3 | 5 | 1 | 1 | 1 | Bajo | 4 | **Fase 1** |
| Verificación de dominio (DNS TXT / fichero) | Autorizar análisis profundo | Pro, Agency | 3 | 5 | 2 | 1 | 1 | Medio | 3 (habilitador) | **Fase 1** |
| Modo profundo: rutas sensibles | Detectar `.git`, `.env`, copias | Pro, Agency | 4 | 4 | 3 | 2 | 3 | Alto (intrusivo) | 5 | **Fase 2** |
| Informe PDF con marca blanca | Entregable a cliente | Agency | 3 | 5 | 2 | 1 | 2 | Bajo | 5 | **Fase 2** |
| Proyectos / clientes y cartera | Gestionar decenas de dominios | Agency | 3 | 5 | 3 | 1 | 2 | Alto (aislamiento) | 5 | **Fase 2** |
| Usuarios, roles y permisos | Equipo de la agencia | Agency | 2 | 4 | 4 | 1 | 3 | Alto | 3 | Fase 3 |
| Informes programados por correo | Automatizar la entrega | Agency | 3 | 4 | 4 | 3 | 3 | Medio | 4 | Fase 3 |
| API para desarrolladores / CI | Bloquear despliegues inseguros | Dev | 4 | 4 | 3 | 2 | 4 | Alto | 3 | Fase 3, si hay demanda |
| *Badge* público de puntuación | Marketing viral | Todos | 3 | 4 | 2 | 2 | 1 | Medio (suplantación) | 3 | A estudiar |
| Gestión de remediaciones / tareas | Seguimiento | Agency | 1 | — | 4 | 1 | 4 | Bajo | 2 | **Descartado** |

## 4. Planes

Estructura propuesta. **Los precios no están fijados**: son una decisión tuya que conviene tomar tras hablar con 5–10 usuarios potenciales. En §8 hay referencias públicas de competidores para situarte.

| | **Free** | **Pro** | **Agency** |
|---|---|---|---|
| Análisis bajo demanda | Sí, sin cuenta, con límite por IP | Sí, límite amplio | Sí, límite amplio |
| Informe web y DNS/correo | Completo | Completo | Completo |
| Vista técnica con evidencias | Sí | Sí | Sí |
| Exportar JSON / imprimir PDF | Sí | Sí | Sí |
| Dominios guardados | — | Varios (p. ej. 5–10) | Muchos (p. ej. 50+) |
| Historial y comparación | — | Sí | Sí |
| Monitorización programada | — | Semanal / diaria | Diaria |
| Alertas (correo) | — | Sí | Sí + *webhook* |
| Análisis profundo (dominio verificado) | — | Sí | Sí |
| Clientes / proyectos | — | — | Sí |
| PDF con marca blanca | — | — | Sí |
| Usuarios y roles | 1 | 1 | Varios |

**Qué va gratis y por qué:** el análisis completo con evidencias. Recortar hallazgos en el plan gratuito destruiría el argumento de confianza; lo que se cobra es **memoria** (historial), **tiempo** (monitorización), **profundidad** (dominio verificado) y **presentación** (marca blanca).

**Hipótesis de retención:** quien configura una monitorización y recibe una alerta útil no se da de baja. La métrica a seguir es «% de cuentas Pro con al menos un dominio monitorizado».

## 5. Arquitectura propuesta

Ninguno de estos servicios está contratado. Todos tienen plan gratuito, pero **elegirlos es decisión tuya**.

| Pieza | Propuesta | Alternativas |
|---|---|---|
| Autenticación | Auth.js (correo con enlace mágico + OAuth de GitHub/Google) | Clerk, Supabase Auth |
| Base de datos | PostgreSQL serverless (Neon o Supabase) | Turso (SQLite), Vercel Postgres |
| ORM / migraciones | Drizzle | Prisma |
| Tareas programadas | Vercel Cron → cola de trabajos en la propia base de datos | Upstash QStash, Inngest |
| Correo transaccional | Resend o Postmark | Amazon SES |
| Pagos | Stripe Checkout + portal de cliente, **solo en modo test** hasta validar el producto | Paddle, Lemon Squeezy (actúan como *merchant of record* y simplifican el IVA) |
| Almacenamiento de informes | JSON del informe en la base de datos (≈ 15 KB por auditoría) | Blob si se guardan PDF |

### Modelo de datos mínimo

```
organization(id, name, plan, stripe_customer_id, created_at)
membership(user_id, organization_id, role)            -- owner | admin | member | viewer
client(id, organization_id, name)                     -- Agency; en Pro hay uno implícito
domain(id, organization_id, client_id, hostname,
       verified_at, verification_token, schedule)     -- none | weekly | daily
audit(id, domain_id, organization_id, engine_version,
      web_score, web_coverage, dns_score, report_json, created_at, trigger)
finding_state(domain_id, check_id, status, severity,
              first_seen_at, last_seen_at)            -- para detectar cambios sin releer JSON
alert(id, domain_id, kind, payload, sent_at)
audit_log(id, organization_id, actor_id, action, target, created_at)
```

Reglas de aislamiento (innegociables):

- **Toda** tabla de datos lleva `organization_id` y **toda** consulta filtra por él desde una capa de acceso única; nunca se confía en un `id` recibido del cliente.
- *Row Level Security* en Postgres como segunda barrera.
- Tests de autorización cruzada: el usuario A no puede leer, comparar ni exportar una auditoría de la organización B, ni conociendo su identificador.

### Detección de cambios y alertas

El motor ya emite hallazgos con identificador estable (`headers.csp`, …). Se compara el estado de cada control con el de la auditoría anterior:

| Cambio | Alerta |
|---|---|
| `pass` → `fail` / `warning` | **Regresión** (siempre) |
| Aparece un fallo crítico (certificado, HTTPS) | **Inmediata** |
| `fail` → `pass` | Resuelto (resumen semanal) |
| `*` → `not_tested` / `error` | **Nunca alerta**; si persiste 3 ejecuciones, aviso de «no podemos analizar tu web» |
| Variación de puntuación < 3 puntos sin cambio de estado | No alerta |

Para evitar falsos positivos y ruido: una regresión se confirma con una **segunda ejecución** unos minutos después antes de avisar, y cada (dominio, control) alerta como máximo una vez hasta que cambie de estado.

### Verificación de dominio

Registro TXT `_webtrustscan-verify.<dominio>` con un *token* aleatorio por (organización, dominio), o fichero `/.well-known/webtrustscan-verify.txt`. Se revalida periódicamente; si desaparece, el dominio vuelve a nivel básico. El análisis profundo comprueba la verificación en el momento de ejecutarse, no al programarse.

## 6. Seguridad de las superficies nuevas

| Superficie | Riesgo | Control requerido |
|---|---|---|
| Monitorización programada | Usar el servicio como bot contra terceros; coste descontrolado | Solo dominios verificados (o límite estricto sin verificar); tope de ejecuciones por organización y global; el cron exige el secreto de Vercel Cron |
| Análisis profundo | Sondeo de rutas en sitios ajenos | Verificación obligatoria; lista cerrada; registro en `audit_log` |
| Informes guardados | XSS almacenado: cabeceras y HTML del sitio analizado acaban en nuestra interfaz | Ya mitigado: React escapa todo, no se usa `dangerouslySetInnerHTML`, CSP con nonce. Mantenerlo así y limitar tamaños de evidencia |
| PDF con marca blanca | Subida de logotipos (SVG con script, ficheros enormes) | Solo PNG/JPEG, re-codificados, tamaño máximo; servir desde un origen aparte |
| *Webhooks* de alerta | **SSRF de nuevo**: el usuario indica una URL a la que llamamos | Reutilizar `safeFetch` con la misma política de IP y puertos |
| Sesiones | Robo de sesión, CSRF | Cookies `__Host-`, `Secure`, `HttpOnly`, `SameSite=Lax`; acciones mutantes con comprobación de origen |
| Stripe | Suplantación de *webhooks* | Verificar firma; el plan se lee de la base de datos, nunca del cliente |
| API pública | Abuso, enumeración | Claves con *hash*, alcance por organización, límite por clave |

Cada una necesita sus tests antes de salir, igual que se hizo con SSRF y rate limiting.

## 7. Privacidad y uso responsable

**Datos que el producto trata hoy:** la URL analizada (en memoria) y un *hash* de la IP para el límite de peticiones (en memoria, o en Upstash con caducidad si se configura). No hay cuentas, *cookies* propias ni registro persistente.

**Con Pro se añaden:** correo e identidad de los usuarios, dominios, informes históricos, datos de facturación (en Stripe) y registros de actividad.

Mecanismos a implementar:

- **Exclusión de dominios:** lista de dominios que no se analizan a petición de su titular, y un contacto de abuso visible (`security.txt` propio, correo `abuse@`).
- **Identificación del analizador:** *User-Agent* propio (`WebTrustScan/2.0`), ya implementado, idealmente con una URL informativa.
- **Conservación:** definir plazos (p. ej. informes mientras la cuenta esté activa; registros de actividad 12 meses; IP nunca en claro).
- **Borrado y exportación** de la cuenta bajo demanda.

**Lo que debes revisar con un profesional antes de publicar Pro** (no puedo darte asesoramiento legal):

1. Titular del servicio y datos fiscales (LSSI-CE: aviso legal).
2. Política de privacidad RGPD: base jurídica, encargados del tratamiento (Vercel, proveedor de base de datos, correo, Stripe), transferencias internacionales, plazos, derechos.
3. Si el *hash* de IP con sal se considera dato personal en tu caso (probablemente sí: es seudonimización, no anonimización).
4. Condiciones de uso: uso permitido (webs propias o autorizadas), prohibición de uso contra terceros, limitación de responsabilidad, «no es una certificación ni un pentest».
5. Política de *cookies* si se añaden analíticas.
6. Fiscalidad de suscripciones a consumidores y empresas de la UE (IVA / OSS).
7. Plan de Vercel: el plan Hobby está limitado a uso personal no comercial (ver `COST_ANALYSIS.md`).

Los borradores de política de privacidad y condiciones de uso **no se han redactado en esta fase**; es una tarea pendiente en `HANDOFF.md`.

## 8. Referencias de mercado

Datos recogidos el 15 de noviembre de 2026 de fuentes secundarias (comparativas y reseñas); varios proveedores no publican precios o las fuentes se contradicen. **Compruébalos en la web de cada proveedor antes de usarlos.**

| Herramienta | Tipo | Precio publicado (según fuentes) |
|---|---|---|
| Mozilla HTTP Observatory | Cabeceras, gratuito | Gratis. Modelo de penalizaciones y bonificaciones sobre 100. |
| Qualys SSL Labs | Configuración TLS, gratuito | Gratis. Referencia en TLS; por eso no lo duplicamos. |
| HostedScan | Escáner de vulnerabilidades (OpenVAS, ZAP, Nmap) | Plan gratuito limitado; de pago desde ~39 $/mes; niveles superiores ~109 y ~189 $/mes (este último con marca blanca). |
| Intruder | Escáner de vulnerabilidades | Fuentes contradictorias: entre ~79 y ~299 $/mes de entrada. |
| Detectify | Superficie de ataque y escaneo de aplicaciones | Fuentes contradictorias: desde ~82–90 €/mes por aplicación hasta planes anuales de miles de euros. |
| Probely | DAST | Fuentes contradictorias (~98 $/mes o «consultar»). |

Lectura: los escáneres de vulnerabilidades de pago empiezan en decenas de dólares al mes y suben rápido; las herramientas de **configuración** son gratuitas y no ofrecen historial, monitorización ni informes para clientes. El hueco de WebTrustScan está entre ambos. No he encontrado datos fiables de cuántos usuarios pagarían por ello: es la hipótesis que hay que validar antes de integrar cobros.

Fuentes: [HTTP Observatory · metodología](https://developer.mozilla.org/en-US/observatory/docs/tests_and_scoring) · [HostedScan vs Intruder](https://hostedscan.com/intruder-alternative) · [HostedScan vs Detectify](https://hostedscan.com/detectify-alternative) · [Reseña de HostedScan](https://geekflare.com/cybersecurity/hostedscan-review/) · [Alternativas a Intruder](https://theguidex.com/resources/best-intruder-alternatives) · [Comparativa de escáneres 2026](https://checkvibe.dev/blog/web-app-security-scanner-comparison)

## 9. Diseño de la experiencia

Implementado en esta fase:

- **Vista «Resumen»** (ejecutiva): nota, cobertura, confianza, puntuación por categoría y los 5 problemas más importantes con su solución.
- **Vista «Técnica»**: todos los hallazgos agrupados (problemas, no comprobado, correcto, no aplica), con evidencias, confianza, peso y referencias.
- **Avisos del análisis** separados de los hallazgos (bloqueo de WAF, error temporal, CDN detectada, SPA).
- **DNS y correo** como informe aparte, con su propia nota.
- **Exportar JSON** e **imprimir a PDF** (despliega todo el detalle técnico y usa una hoja de estilos de impresión).

Pendiente para Pro: panel con la cartera de dominios (nota, tendencia, última auditoría, alertas abiertas), ficha de dominio con gráfica de evolución, comparador de dos auditorías lado a lado y pantalla de alertas.
