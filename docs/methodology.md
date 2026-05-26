# Metodología de la auditoría pasiva

Este documento explica las decisiones técnicas y éticas detrás del script `audit.py`. Sirve de complemento al artículo académico que se construye sobre los hallazgos.

## Fundamento

La auditoría pasiva se diferencia de la prueba de penetración (pen-test) en que **no interactúa con el sistema más allá de lo que cualquier visitante normal haría**. La distinción importa por dos razones:

1. **Legal**: las pruebas pasivas no requieren autorización del propietario en la mayoría de jurisdicciones, porque solo procesan información que el sistema entrega voluntariamente.
2. **Reproducible**: cualquier investigador puede repetir los hallazgos sin coordinación previa con el propietario, lo cual es importante para la falsabilidad del estudio.

El criterio operativo que aplicamos es: **si un navegador con un usuario sentado al teclado podría ver esa información sin engañar al servidor, está dentro del alcance pasivo**.

## Marco de referencia

El catálogo de hallazgos se mapea a **OWASP API Security Top 10:2023**, publicado en junio de 2023. Esta versión incorpora cambios relevantes respecto a la edición de 2019:

- Combina las anteriores categorías "Excessive Data Exposure" y "Mass Assignment" en una nueva: **API3 - Broken Object Property Level Authorization (BOPLA)**.
- Agrega **API6 - Unrestricted Access to Sensitive Business Flows**.
- Agrega **API10 - Unsafe Consumption of APIs**.

Aunque el script no detecta directamente algunas categorías (BOLA, BFLA) por requerir interacción autenticada, sí cubre extensivamente:

- **API2** - Broken Authentication (cookies inseguras, formularios sin HTTPS)
- **API3** - BOPLA (cabeceras de cache mal configuradas)
- **API8** - Security Misconfiguration (cabeceras faltantes, TLS débil, info disclosure)
- **API9** - Improper Inventory Management (endpoints expuestos sin documentar)
- **API10** - Unsafe Consumption of APIs (falta de security.txt para reportar issues)

## Técnicas aplicadas

### 1. Inspección de cabeceras HTTP

Todas las cabeceras se obtienen de una única respuesta GET sobre la URL principal. No se hacen peticiones adicionales para enumerar variantes. La interpretación sigue:

- **Cabeceras obligatorias** (lista blanca): si no están presentes, es hallazgo.
- **Cabeceras de filtración** (lista negra): si están presentes, es hallazgo.

### 2. Análisis de cookies

Las flags de seguridad (Secure, HttpOnly, SameSite) se evalúan parseando el header `Set-Cookie` crudo, ya que el `RequestsCookieJar` de la librería pierde algunos atributos al procesar la respuesta.

### 3. Validación TLS

Se realiza un handshake TLS completo (sin envío de datos de aplicación). Se evalúa:

- Versión negociada (TLS 1.0 y 1.1 deprecadas por RFC 8996).
- Validez temporal del certificado.
- Emisor del certificado (sin validación de cadena exhaustiva).

### 4. Parseo de HTML público

Se descarga el HTML servido a una petición GET sin autenticación y se analiza con BeautifulSoup. Las búsquedas son:

- Comentarios HTML con patrones sospechosos (TODO, FIXME, credenciales, IPs internas).
- Meta tag `generator`.
- Formularios con `action` HTTP plano o inputs `password` con autocomplete habilitado.
- Recursos externos cargados por HTTP en página HTTPS (mixed content).

### 5. Detección de endpoints API

Se aplican patrones regex sobre el HTML completo para encontrar referencias a:

- `/api/v\d+/...`
- `/rest/...`
- `/graphql`
- `/swagger`, `/openapi.json`, `/api-docs`
- Endpoints OAuth (`/oauth/token`, `/oauth/authorize`)

### 6. Lectura de archivos estandarizados

Se descargan los archivos públicos definidos por estándares web:

| Archivo | Estándar |
|---|---|
| `/robots.txt` | De facto desde 1994 |
| `/sitemap.xml` | Sitemaps Protocol |
| `/.well-known/security.txt` | RFC 9116 |
| `/humans.txt` | humanstxt.org |

Especial atención a `robots.txt`: si lista rutas sensibles bajo `Disallow:`, eso le da al atacante un mapa de dónde buscar (paradójicamente, el archivo creado para "ocultar" rutas las expone).

### 7. Análisis de redirecciones

Se sigue la cadena completa de redirecciones para detectar:

- Cadenas excesivamente largas (>3 saltos).
- Redirecciones que pasan por HTTP plano antes de llegar a HTTPS.

## Restricciones éticas autoimpuestas

- No se intentan credenciales por defecto.
- No se enumera por fuerza bruta directorios o archivos.
- No se prueban endpoints conocidos por ser vulnerables (e.g., `/.env`, `/.git/config`) por considerarse en zona gris ética.
- No se usan exploits públicos (Metasploit, etc.).
- Se respeta el `Crawl-delay` declarado en `robots.txt` (aunque el script tiene un solo request por endpoint, así que no aplica en la práctica).

## Reproducibilidad

El código fuente está disponible en GitHub bajo licencia MIT. Cualquier investigador puede:

1. Clonar el repositorio.
2. Modificar la lista `TARGETS` con sus propios sistemas a auditar.
3. Ejecutar `python src/audit.py`.
4. Comparar sus reportes con los publicados.

Los hallazgos son determinísticos en el sentido de que, dada la misma respuesta del servidor, el script produce los mismos resultados. Sin embargo, los servidores pueden cambiar su configuración entre auditorías, por lo que se recomienda registrar la fecha exacta de cada análisis (el script lo hace automáticamente en cada hallazgo).
