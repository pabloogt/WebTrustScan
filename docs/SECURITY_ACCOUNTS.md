# SECURITY_ACCOUNTS — Seguridad de cuentas, sesiones y datos

**Actualizado:** 16 de noviembre de 2026. Sustituye a la auditoría del sistema anterior (autenticación propia con scrypt), que se ha retirado por completo.

Leyenda de verificación usada en todo el documento:

- **[BD]** probado sobre PostgreSQL con las migraciones reales (`tests/db`).
- **[APP]** probado por las rutas reales de la aplicación con un doble de Supabase Auth (`tests/accounts`).
- **[SIN VERIFICAR]** implementado, pero no ejecutado contra Supabase real.

## 1. Arquitectura

```
Navegador ──(mismo origen, cookies HttpOnly)──▶ Rutas de Next.js ──▶ Supabase Auth  (usuarios, contraseñas, sesiones)
                                                      │
                                                      ├─ cliente de SESIÓN  (clave pública + JWT del usuario) ──▶ PostgreSQL con RLS
                                                      └─ cliente de SERVICIO (clave secreta, solo servidor)   ──▶ cuota, eventos, borrado
```

- **Una sola autenticación.** Usuarios, contraseñas y sesiones viven en Supabase Auth. El código propio de contraseñas (scrypt) y sesiones se ha eliminado: no queda ninguna vía de acceso paralela.
- **El navegador nunca habla con Supabase.** Todas las operaciones pasan por rutas del servidor. No hay claves ni tokens accesibles desde JavaScript y la CSP conserva `connect-src 'self'`.
- **La clave secreta solo se usa en tres sitios:** las funciones de consumo de cuota, el registro de eventos de seguridad y el borrado de cuenta. Todo lo demás se lee con la sesión del usuario, bajo RLS.

## 2. Autenticación

| Aspecto | Implementación | Verificación |
|---|---|---|
| Registro | Correo y contraseña (10–72 caracteres). Supabase envía el enlace de confirmación. | [APP] · envío real [SIN VERIFICAR] |
| No enumeración en el alta | La respuesta es idéntica exista o no la cuenta. Depende de que *Confirm email* esté activado en Supabase. | [APP] |
| Confirmación de correo | Sin confirmar no hay sesión; además la aplicación descarta cualquier usuario sin `email_confirmed_at`. | [APP] |
| Acceso | Un único mensaje para contraseña incorrecta, cuenta inexistente, correo sin confirmar y entrada malformada. | [APP] |
| Fuerza bruta | 10 intentos por minuto por IP **y** 10 por cuarto de hora por cuenta (protege frente a ataques distribuidos). Más los límites propios de Supabase. | [APP] |
| Recuperación | Respuesta idéntica exista o no la cuenta y se envíe o no el correo; como mucho un correo por minuto y 3 por hora por cuenta, y 5 solicitudes por hora por IP. La pantalla espera 60 s antes de dejar pedir otro (igual que `max_frequency` de Supabase). Si Supabase rechaza el envío, el motivo (p. ej. `over_email_send_rate_limit`) se registra en el log del servidor y en `security_events` como `recovery_not_sent`, sin el correo. | [APP] · envío real [SIN VERIFICAR] |
| Enlaces de correo | La página `/auth/confirm` **no canjea el enlace al abrirse**: muestra un botón y el canje lo hace `POST /api/auth/confirm` (mismo origen). Así, un filtro antispam o una vista previa que abra el enlace no gasta el token de un solo uso, que era la causa más probable de «el enlace ha caducado» en la primera visita. Admite `token_hash` + `type` (plantillas propias) y `code` (enlace predeterminado de Supabase, flujo PKCE), y reconoce los errores que Supabase añade a la URL (`error_code=otp_expired`) para ofrecer pedir otro enlace. Un solo uso; caducan en una hora (no se ha cambiado). | [APP] · contra Supabase [SIN VERIFICAR] |
| Redirección tras el enlace | Solo a rutas internas; una URL absoluta, `//host` o `..` se sustituyen por `/panel`. | [APP] |
| Contraseñas débiles o filtradas | Las rechaza Supabase (la comprobación de filtraciones depende del plan). | [SIN VERIFICAR] |
| CAPTCHA | No integrado. Supabase admite Turnstile y hCaptcha; activarlo exige una cuenta del proveedor y ampliar la CSP. Recomendado si aparecen altas automatizadas. | No implementado |

## 3. Sesiones y cookies

| Aspecto | Implementación |
|---|---|
| Quién emite la sesión | Supabase Auth (token de acceso de 1 h + token de renovación con rotación). |
| Cookies | Las fija el servidor: `HttpOnly`, `SameSite=Lax`, `Path=/` y `Secure` en producción. |
| Renovación | `proxy.ts` renueva la sesión antes de renderizar una página, solo si las cuentas están activadas y la petición trae cookie de sesión. |
| Validación | Cada ruta llama a `auth.getUser()`, que valida el token contra Supabase; no se confía en el contenido de la cookie. |
| Cierre de sesión | Local, o de **todas** las sesiones de la cuenta desde la configuración. |
| Cambio de contraseña | Cierra las demás sesiones y deja constancia en el registro de seguridad. |
| Rutas privadas | Las páginas `/panel` y `/cuenta/nueva-contrasena` se comprueban en el servidor y redirigen a `/acceso`; las rutas de API responden 401. |

Todo lo anterior está [APP] para la lógica propia y [SIN VERIFICAR] para el comportamiento real de las cookies de Supabase en un dominio HTTPS.

**Pase de recuperación.** Tras canjear un enlace de recuperación se puede fijar una contraseña nueva sin conocer la anterior durante 15 minutos. Lo acredita una cookie `HttpOnly` firmada con HMAC y ligada al usuario; es de un solo uso. Solo se concede por un enlace `type=recovery` o por un `code` cuyo destino sea `/cuenta/nueva-contrasena` (destino que fija la propia aplicación al pedir la recuperación). Sin ese pase —por ejemplo, con una sesión robada— cambiar la contraseña, el correo o borrar la cuenta exige la contraseña actual. Si el pase caduca en la pantalla de recuperación, el mensaje lo dice y ofrece pedir otro enlace (antes decía «La contraseña actual no es correcta»). [APP]: pase inventado, caducado o de otro usuario se rechazan.

## 4. CSRF y validación de origen

- Toda petición que no sea GET exige cabecera `Origin` con el mismo host que la aplicación; sin ella o con otro host, 403.
- Los cuerpos deben ser JSON de 8 KB como máximo.
- En `/api/analyze`, una petición de otro origen se trata como **anónima**: nunca consume la cuota de una cuenta.
- Los enlaces de los correos se construyen con `APP_BASE_URL`, no con la cabecera `Host`.

[APP] en ocho rutas y en el analizador.

## 5. Roles

| Rol | Dónde vive | Quién puede cambiarlo |
|---|---|---|
| Usuario | Cualquier cuenta | — |
| Administrador | Tabla `app_admins`, sin ninguna política RLS | Solo quien tenga acceso directo a la base de datos |
| Propietario / miembro de un espacio | `workspace_members.role` | Solo el servidor; el usuario no tiene permiso de escritura |

El rol es independiente del plan. **Hoy ser administrador no desbloquea nada**: no existe panel ni función de administración. La tabla está para no tener que rediseñar después. [BD]: un usuario no puede leer ni escribir `app_admins`.

## 6. Base de datos y RLS

Diez tablas en `public`, **todas con RLS activado** [BD].

| Tabla | El usuario puede | Nunca puede |
|---|---|---|
| `profiles` | Ver y editar `display_name` del suyo | Ver otros perfiles, cambiar `id` o fechas, borrar |
| `workspaces` | Ver los suyos, renombrar el propio | Crear espacios, cambiar el propietario |
| `workspace_members` | Ver sus pertenencias | Añadirse a un espacio, cambiar su rol |
| `subscriptions` | Ver la de sus espacios | Cambiar plan, estado, periodo o identificadores |
| `audits` | Ver y borrar los de sus espacios | Insertar o modificar análisis |
| `usage_events` | Ver los de sus espacios | Insertar, modificar o borrar consumo |
| `usage_carryover`, `usage_carryover_events`, `app_admins`, `security_events`, `billing_webhook_events` | Nada | Nada (sin políticas: solo servidor) |

Dos capas independientes:

1. **Permisos.** Se revocan todos y se conceden solo los necesarios, por columna cuando aplica (`grant update (display_name)`). Sin permiso, la operación falla con `42501` aunque una política lo permitiera.
2. **Políticas RLS.** Filtran las filas: cada usuario ve solo las de espacios a los que pertenece.

Las funciones que consumen cuota (`reserve_audit_rolling`, `workspace_usage_rolling`, `record_account_deletion_rolling`, `rolling_usage`, `quota_window`, `complete_audit`, `finish_audit`, y las anteriores `reserve_audit`, `workspace_usage` y `record_account_deletion`) solo son ejecutables por `service_role`.

### Pruebas de aislamiento [BD]

`npm run test:db` · `tests/db/rls.test.ts` (20 pruebas). Escenario obligatorio, ejecutado tal cual:

| Paso | Resultado |
|---|---|
| Crear usuarios A y B; crear un análisis para A | — |
| B consulta el análisis de A por identificador, por espacio y por dominio | 0 filas |
| B intenta modificarlo | `42501` permiso denegado |
| B intenta borrarlo | 0 filas afectadas; el análisis sigue intacto |
| B consulta el espacio, las pertenencias, la suscripción, el consumo y el perfil de A | 0 filas |
| B intenta añadirse al espacio de A o cambiar el propietario | `42501` |
| B intenta ponerse el plan Pro, cambiar el estado o el periodo | `42501` |
| B intenta hacerse administrador o cambiar su rol | `42501` |
| B intenta borrar, alterar o insertar consumo | `42501` |
| B intenta ejecutar las funciones de cuota del servidor | `42501` |
| Visitante sin sesión intenta leer cualquier tabla | `42501` |

A nivel de aplicación [APP]: con el identificador de un informe ajeno, la ruta responde 404, igual que con uno inexistente; identificadores malformados (`' or 1=1`, `../`) dan 404 sin error interno; la exportación de una cuenta no contiene datos de otra.

**Limitación:** estas pruebas ejecutan el SQL real en PostgreSQL, con el rol y el JWT que usa Supabase, pero no a través de la API de Supabase. Cuando haya Docker, repítelas contra Supabase local.

## 7. Límites de frecuencia

Definidos en `lib/plans.ts`, aplicados por `lib/limits.ts` con `@upstash/ratelimit`.

| Límite | Valor |
|---|---|
| Altas por IP | 5 por hora |
| Accesos por IP / por cuenta | 10 por minuto / 10 por 15 minutos |
| Recuperaciones por IP / por cuenta | 5 por hora / 3 por hora |
| Canjes de enlaces por IP | 20 por 10 minutos |
| Cambios de cuenta por usuario | 10 por 10 minutos |
| Análisis por usuario | 6 por minuto (además de la cuota) |
| Analizador: por cliente / global | 10 por minuto / 120 por minuto |
| Visitantes sin cuenta | 2 análisis al día por IP, uno a la vez |

- **Identificación de la IP.** En Vercel, la cabecera de la plataforma (`x-vercel-forwarded-for`); nunca un `X-Forwarded-For` escrito por el cliente. [APP]
- **Sin IP en claro.** Las claves son HMAC-SHA256 con `IP_HASH_SECRET`. [APP]
- **Sin Upstash en producción, 503.** El analizador y las rutas de cuentas no funcionan sin control de abuso. Solo `RATE_LIMIT_ALLOW_MEMORY=true` permite, de forma explícita, límites por instancia. [APP] y comprobado a mano con el servidor de producción local.
- **Si Redis falla en marcha**, se degrada a memoria local: el límite se debilita pero no desaparece. [APP]
- **Upstash real: [SIN VERIFICAR].**

## 8. Borrado y exportación de la cuenta

- **Exportar:** descarga un JSON con perfil, espacios, suscripción, análisis y consumo, leído con la sesión del usuario. [APP]
- **Eliminar:** exige contraseña y escribir `ELIMINAR`. Borra el usuario en Supabase Auth y, en cascada, perfil, espacio, pertenencias, suscripción, análisis y consumo. [APP] [BD]
- **Lo único que se conserva:** la fecha de cada análisis que aún cuenta en la ventana de 7 días, bajo un HMAC del correo (`usage_carryover_events`); se purga a los 31 días. Sirve para que darse de baja y volver a registrarse no reinicie la cuota. No permite recuperar el correo. Los arrastres anteriores del sistema mensual (`usage_carryover`) se siguen leyendo y no se han borrado.
- Los eventos de seguridad de la cuenta borrada quedan sin identificador de usuario y se purgan a los 90 días con `purge_security_events()` (hay que programarla: no se ejecuta sola).

## 9. Registro de seguridad

Tabla `security_events`: alta solicitada, acceso fallido, recuperación solicitada, recuperación no enviada (con el motivo), contraseña cambiada, cambio de correo solicitado, cuenta eliminada. Guarda tipo, fecha, identificador de usuario cuando procede y HMAC de la IP. **Nunca** contraseñas, tokens, correos ni IP en claro. [APP]

No se registran todavía los accesos correctos ni los cambios de plan o de rol (no existe ninguna ruta que los haga).

## 10. Problemas del sistema anterior y su estado

| Problema | Estado |
|---|---|
| Autenticación propia con scrypt y sesiones en base de datos | **Retirada por completo** |
| Parámetros de scrypt leídos del hash sin acotar | Ya no aplica: el código no existe |
| El registro revelaba qué correos tenían cuenta | **Corregido** |
| Sin verificación de correo ni recuperación de contraseña | **Implementado** (envío real pendiente de Resend) |
| Límite de intentos solo en memoria y solo por IP | **Corregido:** Upstash, por IP y por cuenta |
| Sin cambio de contraseña ni cierre de otras sesiones | **Implementado** |
| Sin registro de accesos | **Parcial:** fallidos sí, correctos no |
| Cuota reiniciable borrando y volviendo a añadir un dominio | **Corregido:** el consumo es un registro del servidor |
| Aislamiento solo en el código de la aplicación | **Corregido:** lo aplica PostgreSQL con RLS |

## 11. Riesgos pendientes

1. **Nada de Supabase Auth está verificado contra el servicio real.** Es la mayor incertidumbre.
2. **Concurrencia real de la cuota.** La reserva bloquea la fila de la suscripción (`for update`), que es el mecanismo correcto, pero solo se ha probado con una conexión.
3. **Tipos escritos a mano** en la capa de Supabase, a falta de los generados.
4. **Sin CAPTCHA** ni detección de correos desechables: quien cree muchas cuentas con correos válidos obtiene 5 análisis por cada una.
5. **Sin caducidad de sesión por inactividad** en el plan gratuito de Supabase.
6. **Los enlaces se canjean con una petición GET.** Es el flujo que recomienda Supabase, pero un escáner de correo que abra los enlaces podría consumirlos. Si ocurre, la alternativa es una página intermedia con botón.
7. **`purge_security_events()` no está programada.**
8. **Sin MFA.**
