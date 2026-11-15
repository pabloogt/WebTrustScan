# AUTH_STORAGE_AUDIT — Cuentas, contraseñas, sesiones y almacenamiento

**Fecha:** 15 de noviembre de 2026 · **Estado de la funcionalidad:** implementada, **desactivada por defecto** y fuera del acceso público.

Este documento describe lo que hace el código hoy, leído línea a línea, no lo que debería hacer. No contiene contraseñas, hashes, sales ni tokens. Durante la auditoría no se ha creado ninguna cuenta ni se ha modificado el sistema de autenticación: el único cambio de código es el interruptor que lo desactiva (§7).

**Veredicto:** la base criptográfica es correcta, pero **no está preparada para cuentas reales en un servicio público**. Las carencias de §6 deben resolverse antes de activarla.

---

## 1. Almacenamiento

### Qué base de datos se usa

PostgreSQL, con SQL parametrizado y sin ORM (`lib/pro/db.ts`). Hay dos adaptadores con la misma interfaz:

| Condición | Motor | Dónde están los datos |
|---|---|---|
| `DATABASE_URL` definida | PostgreSQL real, mediante la librería `pg` (pool de 3 conexiones) | En el servidor que indique esa URL |
| Sin `DATABASE_URL`, `NODE_ENV=development` | **PGlite** (PostgreSQL compilado a WebAssembly, dentro del proceso de Node) | Carpeta `.data/pglite/` en la raíz del proyecto |
| Sin `DATABASE_URL`, `NODE_ENV=test` | PGlite en memoria | En ningún sitio: desaparece al terminar el test |
| Sin `DATABASE_URL`, `NODE_ENV=production` | Ninguno | Las rutas responden 503 (y hoy, antes que eso, 404 por el interruptor) |

**Hoy no hay ninguna base de datos de producción.** No se ha conectado Neon ni ningún otro servicio.

### En local

- **Ubicación física:** `.data/pglite/`, ficheros del formato interno de PostgreSQL. Está en `.gitignore`: no entra en el repositorio.
- **Sin cifrar en disco:** quien pueda leer esa carpeta puede leer la base de datos (los correos en claro; las contraseñas y los tokens, solo como hash).
- **Al reiniciar el servidor:** los datos se conservan; las sesiones siguen siendo válidas hasta que caducan.
- **Si se borra `.data/pglite/`:** se pierden todas las cuentas, organizaciones, dominios, auditorías y sesiones. Al siguiente uso se crea una base vacía con las migraciones aplicadas. No hay copia de seguridad automática.
- En esta máquina existe una carpeta `.data/` de las pruebas de la fase anterior, con una cuenta de prueba. No se ha tocado.

### PGlite frente a PostgreSQL real

| | PGlite | PostgreSQL (p. ej. Neon) |
|---|---|---|
| Proceso | Dentro de Node, un solo proceso | Servidor independiente |
| Concurrencia | Una conexión; dos procesos no pueden abrir la misma carpeta | Múltiples conexiones |
| Persistencia en serverless | **No sirve:** en Vercel el disco es efímero y de solo lectura | Sí |
| Copias, réplicas, cifrado en reposo | No | Según el proveedor |
| SQL y tipos | Los mismos (uuid, jsonb, timestamptz) | — |

Los 107 tests de cuentas se ejecutan sobre PGlite. **El adaptador `pg` no se ha ejecutado nunca contra un PostgreSQL real**: es código corto y estándar, pero no está verificado.

### Al configurar `DATABASE_URL`

La aplicación deja de usar PGlite y abre un pool `pg` contra esa URL. Al primer uso crea la tabla `schema_migrations` y aplica las migraciones pendientes de `lib/pro/schema.ts`, cada una en una transacción. Los datos locales de `.data/pglite/` **no se copian**: la base nueva empieza vacía.

### Migrar los datos locales a Neon

Es posible porque el esquema y el SQL son idénticos, pero **no hay ninguna herramienta escrita**. Habría que exportar las filas tabla a tabla y cargarlas en el destino. Dado que los datos locales son solo de prueba, lo razonable es no migrarlos.

---

## 2. Esquema

Migración `001_base` (`lib/pro/schema.ts`). Ninguna tabla guarda contraseñas ni tokens en claro.

| Tabla | Campos | Notas |
|---|---|---|
| `users` | `id` (uuid), `email` (texto, en minúsculas), `password_hash` (texto), `created_at` | Índice único sobre `lower(email)`. No hay campo de correo verificado, ni de último acceso, ni de intentos fallidos. |
| `organizations` | `id`, `name`, `plan` (`free`/`pro`/`agency`), `created_at` | El plan solo se cambia a mano. |
| `memberships` | `user_id`, `organization_id`, `role` (`owner`/`admin`/`member`/`viewer`), `created_at` | Clave primaria compuesta. Hoy cada usuario tiene una sola organización. |
| `sessions` | `token_hash` (clave primaria), `user_id`, `created_at`, `expires_at` | Solo el SHA-256 del token. No guarda IP ni navegador. |
| `domains` | `id`, `organization_id`, `hostname`, `verification_token`, `verified_at`, `verified_method`, `created_at` | Único por (organización, dominio). El token de verificación sí va en claro: no es una credencial de acceso. |
| `audits` | `id`, `organization_id`, `domain_id`, `created_by`, `engine_version`, puntuaciones, `open_findings`, `report` (jsonb), `created_at` | El informe completo. No contiene valores de cookies del sitio analizado. |
| `activity_log` | `id`, `organization_id`, `user_id`, `action`, `target`, `created_at` | Solo altas, bajas y verificaciones de dominios. **No registra accesos.** |

Borrar una organización borra en cascada sus dominios y auditorías; borrar un usuario borra sus sesiones.

---

## 3. Contraseñas

Implementación en `lib/pro/auth.ts`, con el módulo `node:crypto` de Node. Se ejecuta en el servidor, dentro de la propia función que atiende la petición.

| Aspecto | Implementación |
|---|---|
| Algoritmo | **scrypt** (`crypto.scrypt`). Es una función de derivación para contraseñas: **hash de un solo sentido, no cifrado**. No existe ninguna clave con la que recuperar la contraseña original. |
| Parámetros | N = 2¹⁵ (32 768), r = 8, p = 3. Memoria por operación ≈ 32 MiB (`maxmem` limitado a 128 MiB). |
| Longitud de la clave derivada | 32 bytes (256 bits). |
| Sal | 16 bytes de `crypto.randomBytes` (generador criptográfico del sistema), **nueva para cada contraseña**. |
| Formato guardado | Un solo texto: `scrypt$N$r$p$<sal en base64>$<clave en base64>`. Los parámetros viajan con el hash, lo que permite cambiarlos en el futuro sin invalidar los antiguos. |
| Normalización | Unicode NFKC antes de derivar, para que la misma contraseña tecleada en dispositivos distintos coincida. |
| Verificación | Se vuelve a derivar con la sal y los parámetros guardados y se compara con `crypto.timingSafeEqual` (**tiempo constante**), comprobando antes que las longitudes coinciden. |
| Usuario inexistente | Se deriva igualmente contra un hash de relleno, para que la respuesta tarde lo mismo exista o no la cuenta. |
| Pepper o secreto externo | **No hay.** No se usa ninguna clave adicional fuera de la base de datos. |
| Texto plano | La contraseña nunca se guarda ni se escribe en logs. Solo existe en memoria durante la petición. |
| Política | Entre 10 y 200 caracteres. Sin reglas de composición (en línea con NIST) y **sin comprobación contra listas de contraseñas filtradas**. |
| Entradas inválidas | Tipos que no son texto o longitudes fuera de rango se rechazan con 400 (registro) o 401 (acceso) sin llegar a derivar. Un hash guardado con formato desconocido devuelve «no coincide». |

### Comparación con OWASP

La guía de almacenamiento de contraseñas de OWASP recomienda, por orden: **Argon2id** (mínimo 19 MiB de memoria, 2 iteraciones, paralelismo 1) y, si no está disponible, **scrypt** con un coste mínimo de N = 2¹⁷, r = 8, p = 1, admitiendo configuraciones equivalentes que cambian memoria por paralelismo. Según la versión de la guía que conozco, N = 2¹⁵, r = 8, p = 3 —la usada aquí— es una de esas equivalentes; la búsqueda hecha hoy confirmó el mínimo de 2¹⁷/p = 1 y otra de las equivalentes, pero no esta en concreto. **Conviene comprobarlo en la [página actual](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) antes de activar las cuentas.**

Por qué scrypt y no Argon2id: scrypt viene incluido en Node; Argon2id habría exigido una dependencia nativa. Es una decisión defendible, no la primera opción de OWASP. No se cambia ahora: cambiar de algoritmo sin una razón concreta no mejora nada y la estructura del hash ya permite migrar más adelante.

Observaciones:

- **Coste en servidor:** cada acceso consume ~32 MiB y decenas o cientos de milisegundos de CPU. Es intencionado, pero convierte el acceso en un vector de denegación de servicio si el límite de peticiones falla (§6.3).
- **Parámetros leídos del hash sin acotar:** al verificar se usan N, r y p tal como están guardados. Solo es explotable por quien ya pueda escribir en la base de datos, pero conviene acotarlos.
- **Sin recálculo al acceder:** si se suben los parámetros, los hashes antiguos no se actualizan solos.

---

## 4. Sesiones

| Aspecto | Implementación |
|---|---|
| Identificador | 32 bytes de `crypto.randomBytes` (256 bits de aleatoriedad), codificados en base64url (43 caracteres). |
| Qué guarda la base de datos | **Solo el SHA-256 del token**, el usuario y las fechas. Con la tabla en la mano no se puede reconstruir un token ni suplantar una sesión. |
| Validación de cada petición | Se lee la cookie, se calcula su SHA-256 y se busca una sesión con ese hash y `expires_at` posterior a ahora. La misma consulta resuelve usuario, organización y rol. Tokens vacíos o de más de 200 caracteres se descartan sin consultar. |
| Caducidad | **30 días fijos** desde el inicio de sesión. No hay caducidad por inactividad ni renovación. |
| Cierre de sesión | Borra la fila en el servidor y vacía la cookie: un token robado deja de servir aunque el navegador lo conserve. |
| Renovación al acceder | Cada inicio de sesión crea un **token nuevo**; nunca se acepta ni se reutiliza un identificador previo a la autenticación, lo que impide la fijación de sesión. Las sesiones anteriores del mismo usuario **siguen siendo válidas**. |
| Limpieza | Las sesiones caducadas de un usuario se borran cuando ese usuario vuelve a acceder. No hay limpieza periódica. |
| Cerrar todas | Existe la función (`destroyAllSessions`) pero ninguna pantalla ni ruta la usa. |

### Cookie

| Atributo | Producción | Desarrollo local |
|---|---|---|
| Nombre | `__Host-wts_session` | `wts_session` |
| `Secure` | Sí | No (HTTP en localhost) |
| `HttpOnly` | Sí | Sí |
| `SameSite` | `Lax` | `Lax` |
| `Path` | `/` | `/` |
| `Domain` | No se establece (lo exige el prefijo `__Host-`) | No se establece |
| Duración | 30 días (`Max-Age`) | 30 días |

El prefijo `__Host-` hace que el navegador rechace la cookie si no es `Secure`, si lleva `Domain` o si la intenta fijar un subdominio. «Producción» significa `NODE_ENV=production`: **en un despliegue de Preview de Vercel también se cumple**, pero esto no se ha comprobado en infraestructura real.

### Rutas privadas

Todas las rutas de datos llaman a `requireSession` y responden 401 sin sesión. Las páginas `/panel` y `/acceso` no contienen datos: los piden a la API. Verificado por test para las 13 combinaciones de ruta y método.

---

## 5. Registro, acceso y control de acceso

| Control | Estado |
|---|---|
| **CSRF** | Toda petición que no sea GET exige cabecera `Origin` con el mismo host que la aplicación (403 si falta o difiere), más `SameSite=Lax` y cuerpo JSON. Probado en el acceso y en las rutas de dominios y auditorías. |
| **Enumeración en el acceso** | Mismo código (401), mismo mensaje y tiempo comparable exista o no la cuenta. |
| **Enumeración en el registro** | **Fallo:** responde 409 «Ya existe una cuenta con ese correo». Ver §6.1. |
| **Límite de intentos** | Acceso: 10 por minuto. Registro: 5 por hora. Verificación de dominio: 10 por minuto. Ver limitaciones en §6.3. |
| **Validación** | Correo con formato básico y máximo 254 caracteres; contraseña de 10 a 200; cuerpos de más de 8 KB rechazados. |
| **Errores** | Los errores esperados devuelven un mensaje seguro; los inesperados, un 500 genérico y el detalle solo en el log del servidor. |
| **Inyección SQL** | Todas las consultas son parametrizadas. Los identificadores se validan como UUID antes de consultarse. |
| **Aislamiento entre organizaciones** | La organización se toma siempre de la sesión, nunca de la petición. Toda consulta filtra por `organization_id`. Un recurso ajeno responde 404, igual que uno inexistente. 15 tests lo cubren por todas las rutas. |
| **Permisos** | Cuatro roles; el de solo lectura no puede añadir, verificar, auditar ni borrar. Probado. No hay forma de invitar usuarios ni de cambiar roles: en la práctica cada cuenta es propietaria de su organización. |

---

## 6. Carencias que impiden activar cuentas reales

Ordenadas por importancia.

1. **El registro revela qué correos tienen cuenta.** Corregirlo bien exige verificación por correo (responder siempre lo mismo y enviar un mensaje), que no existe.
2. **No hay verificación de correo ni recuperación de contraseña.** Cualquiera puede registrar una dirección ajena, y quien olvide su contraseña pierde la cuenta. Ambas cosas requieren un servicio de correo.
3. **El límite de intentos es frágil.**
   - Vive en memoria: en serverless cada instancia cuenta por separado.
   - Es por IP, no por cuenta: no hay bloqueo progresivo de una cuenta atacada desde muchas IP.
   - Si la aplicación no puede identificar la IP del cliente de forma fiable (fuera de Vercel y sin `TRUSTED_PROXY_HOPS`), **todos los clientes comparten un único contador**: diez intentos fallidos de cualquiera bloquean el acceso a todos durante un minuto.
4. **Sin caducidad por inactividad ni gestión de sesiones.** 30 días fijos, sin lista de sesiones abiertas ni «cerrar las demás».
5. **Sin cambio de contraseña.** No hay ruta para cambiarla y, por tanto, tampoco se invalidan sesiones al hacerlo.
6. **Sin registro de accesos.** No queda constancia de inicios de sesión ni de intentos fallidos.
7. **Sin comprobación de contraseñas filtradas** ni segundo factor.
8. **El adaptador de PostgreSQL real no está probado**, ni el comportamiento de las cookies en Vercel.
9. **Parámetros de scrypt sin acotar al verificar** y sin recálculo de hashes antiguos.
10. **Base de datos local sin cifrar** (aceptable en desarrollo; irrelevante en producción con un proveedor).
11. **Privacidad y legal:** almacenar correos convierte al servicio en responsable de datos personales. Hacen falta política de privacidad, base jurídica y procedimiento de borrado.
12. **Modelo de producto:** el límite de un dominio por cuenta se salta borrando y volviendo a añadir (observación tuya, correcta).

---

## 7. Estado: desactivadas por defecto

`lib/pro/config.ts` define `accountsEnabled()`: devuelve `true` **solo** si la variable de entorno de servidor `ACCOUNTS_ENABLED` vale exactamente `true`. Ausente, vacía, `1`, `TRUE`, `yes`… dejan las cuentas desactivadas. La variable no lleva el prefijo `NEXT_PUBLIC_`: no llega al navegador ni puede cambiarse desde él.

Con las cuentas desactivadas:

- **Las 13 rutas de la API responden 404** antes de abrir la base de datos, de leer el cuerpo y de comprobar la sesión (`route()` en `lib/pro/http.ts`). No se puede registrar, acceder ni usar una sesión que antes fuera válida.
- **Las páginas `/acceso` y `/panel` responden 404** (se decide en el servidor).
- **La portada no muestra el enlace al panel.**
- **El analizador público no cambia.**

No se ha borrado nada: tablas, migraciones, código de autenticación, pantallas y tests siguen ahí.

Comprobado de dos formas: 44 tests automáticos (`tests/pro/disabled.test.ts`, que además verifican que ninguna ruta llega a consultar la base de datos) y una prueba manual contra el servidor de producción local (`next start`) sin ninguna variable definida.

### Para activarlas en local (desarrollo)

Crear `.env.local` con `ACCOUNTS_ENABLED=true` y reiniciar `npm run dev`. `.env*` está en `.gitignore`.

## 8. Requisitos para activarlas en público

1. Proveedor de correo y, con él: verificación de la dirección, recuperación de contraseña y registro que no revele cuentas existentes.
2. Límite de intentos compartido entre instancias y con protección por cuenta, además de la regla del WAF.
3. Cambio de contraseña con cierre de las demás sesiones; caducidad por inactividad.
4. Registro de accesos e intentos fallidos.
5. Base de datos PostgreSQL contratada, con el adaptador probado en Preview y copias de seguridad.
6. Comprobar en Preview la cookie `__Host-`, `Secure` y la protección de origen.
7. Confirmar los parámetros de scrypt con la guía vigente de OWASP y acotarlos al verificar.
8. Política de privacidad, condiciones de uso y procedimiento de borrado de cuenta.
9. Decidir el modelo de límites, que hoy no aporta valor.
10. Una revisión de seguridad específica de este módulo con esas piezas ya construidas.
