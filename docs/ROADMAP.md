# ROADMAP

Ordenado por dependencia y valor, no por fechas. Cada bloque indica qué necesita de ti antes de poder empezar.

## Hecho en esta fase (15 de noviembre de 2026)

- Continuidad de las auditorías 1 y 2 verificada (222/222 tests).
- Diagnóstico de 11 anomalías del motor 1.x, todas reproducidas en laboratorio.
- **Engine 2.0**: catálogo central, 24 controles en 8 categorías, 7 estados, evidencias, confianza, scoring desacoplado con cobertura, topes e informes independientes (web / DNS y correo).
- Capa de red ampliada (certificado, cookies, cuerpo acotado, sonda TLS) sin relajar SSRF.
- Laboratorio HTTP/HTTPS con CA propia y DNS simulado: 31 escenarios comparando ambos motores.
- Interfaz nueva: vistas resumen y técnica, avisos del análisis, exportar JSON, imprimir a PDF.
- CI (GitHub Actions) preparado: lint, tipos, tests, build y `npm audit`.
- 324 tests en total.

## 0. Antes de desplegar (requiere tu intervención)

| Tarea | Por qué | Quién |
|---|---|---|
| Revisar los cambios y hacer *commit* | Hay tres rondas de trabajo sin commitear en el árbol | Tú (o pídemelo) |
| Probar con dominios **propios** en local (`npm run dev`) | El motor no se ha ejecutado contra Internet | Tú |
| Desplegar en **Preview** y repetir | Validar DNS, sonda TLS y duración en el runtime de Vercel | Tú autorizas |
| Crear la regla de *rate limit* del WAF de Vercel para `/api/analyze` | Primera línea contra abuso, gratis en Hobby | Tú (cuenta de Vercel) |
| Bajar `RATE_LIMIT_GLOBAL_PER_MINUTE` (p. ej. 30) | Acotar coste y abuso mientras no haya ingresos | Tú decides el valor |
| Activar alertas de gasto y de errores en Vercel | Hoy no hay monitorización operativa | Tú |

## 1. Calibración del motor con webs reales

*Necesita:* una lista de 20–30 dominios propios o con permiso.

- Comparar los resultados con el criterio de alguien que conozca cada web; ajustar pesos y créditos donde la nota no convenza.
- Capturar respuestas reales de bloqueo (Cloudflare, Akamai, etc.) y añadirlas como *fixtures* del laboratorio.
- Medir duración real y tasa de `NOT_TESTED`.
- Decidir si la CSP débil debe impedir la nota A.

## 2. Mejoras del motor que no necesitan cuentas

- **DNSSEC** mediante DNS-over-HTTPS (evaluar proveedor y privacidad).
- **DKIM** informativo con selectores comunes.
- Cookies y HSTS de **todos los saltos** de la redirección, no solo del final.
- Detección de tecnologías como dato informativo (sin puntuar).
- Enlace a SSL Labs para el detalle de cifrados.
- Página `/metodologia` pública generada desde el catálogo.
- *User-Agent* con URL informativa y página de exclusión de dominios.

## 3. Base de WebTrustScan Pro

*Necesita:* elegir proveedor de autenticación y de base de datos; pasar a Vercel Pro si va a ser comercial.

1. Cuentas y organizaciones (esquema multi-organización desde el inicio).
2. Guardar auditorías e historial por dominio.
3. Comparador de dos auditorías.
4. Panel de dominios: nota, tendencia, última auditoría.
5. Tests de aislamiento entre organizaciones.

## 4. Monitorización y alertas

*Necesita:* proveedor de correo transaccional.

1. Verificación de propiedad del dominio (TXT o fichero).
2. Auditorías programadas (semanal / diaria) con cola y concurrencia limitada.
3. Detección de cambios con doble confirmación antes de alertar.
4. Alertas por correo: regresiones, certificado próximo a caducar.

## 5. Análisis profundo (solo dominios verificados)

1. Rutas sensibles con verificación de contenido (lista cerrada).
2. Métodos HTTP.
3. Rastreo limitado del propio dominio (≤ 10 páginas).

## 6. Agency

1. Clientes y proyectos; cartera de dominios.
2. PDF con marca blanca.
3. Usuarios, roles y permisos.
4. Informes programados.

## 7. Monetización

*Necesita:* validar la disposición a pagar con usuarios reales; revisión legal y fiscal.

1. Entrevistas con 5–10 desarrolladores y agencias.
2. Aviso legal, política de privacidad y condiciones de uso revisadas por un profesional.
3. Stripe en modo test → cobros reales solo cuando el motor esté calibrado y la monitorización lleve semanas sin falsos positivos.

## Descartado (y por qué)

- Correlación de *banners* con CVE: demasiados falsos positivos.
- Gestión de tareas de remediación: las agencias ya tienen su herramienta.
- SEO y rendimiento: otro producto.
- Configuración TLS exhaustiva: SSL Labs lo hace gratis y mejor.
