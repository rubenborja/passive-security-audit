# Auditor Pasivo de Seguridad Web

Herramienta en Python para evaluar la postura de seguridad de aplicaciones web públicas, sin pruebas intrusivas. El catálogo de hallazgos sigue el marco **OWASP API Security Top 10:2023**.

Este proyecto fue desarrollado como parte de un estudio académico sobre vulnerabilidades en sistemas web públicos de Ecuador. El reporte está enriquecido con **vector de ataque**, **escenario concreto** e **impacto** para cada hallazgo, de manera que la salida del script sea directamente utilizable en la sección de discusión de un artículo científico.

## ¿Qué hace?

Solo cosas que cualquiera podría revisar manualmente con un navegador y `curl`. La diferencia es que aquí están automatizadas, categorizadas, mapeadas a OWASP y acompañadas de un análisis de riesgo legible.

| Módulo | Qué revisa |
|---|---|
| Cabeceras HTTP | Presencia/ausencia de HSTS, CSP, X-Frame-Options, Referrer-Policy, Permissions-Policy, COOP, CORP, Cache-Control |
| Cabeceras que filtran | Server, X-Powered-By, X-AspNet-Version, X-Generator, X-Backend-Server, Via, X-Runtime, etc. |
| Cookies | Flags Secure, HttpOnly, SameSite. Detección de nombres reveladores (PHPSESSID, JSESSIONID, etc.) |
| CORS | Detecta `Access-Control-Allow-Origin: *` con credenciales habilitadas |
| TLS | Versión negociada (TLS 1.0/1.1 deprecadas), expiración del certificado, emisor |
| HTML público | Meta tag generator, comentarios HTML sospechosos, formularios sin HTTPS, autocomplete en passwords, mixed content |
| Endpoints API | Búsqueda de `/api/v*`, `/graphql`, `/swagger`, `/openapi.json`, `/rest/`, etc. en el HTML/JS |
| Archivos estandarizados | robots.txt (rutas sensibles), sitemap.xml, security.txt (RFC 9116), humans.txt |
| Redirecciones | Cadenas largas, redirección por HTTP plano |

## Lo que NO hace (por diseño)

- No envía payloads de inyección
- No prueba credenciales por fuerza bruta
- No accede a recursos autenticados
- No enumera directorios ocultos
- No realiza fuzzing de parámetros
- No ejecuta exploits

Todo lo que el script obtiene está disponible para cualquier visitante normal del sitio.

## Instalación

Requiere Python 3.8 o superior.

```bash
git clone https://github.com/rubenborja/passive-security-audit.git
cd passive-security-audit
pip install -r requirements.txt
```

## Uso

Edita la lista `TARGETS` al inicio de `src/audit.py` con los sitios que quieras auditar:

```python
TARGETS = [
    {
        "nombre": "Mi sitio",
        "url": "https://ejemplo.com/ruta",
    },
]
```

Y ejecuta:

```bash
python src/audit.py
```

Los reportes se generan en la carpeta `reports/`:

- `reporte_seguridad.xlsx` - Excel con cuatro hojas:
  - **Resumen ejecutivo**: tabla compacta con conteo por severidad para cada sistema (lista para incluir en el paper).
  - **Hallazgos detallados**: una fila por hallazgo, 16 columnas con vector, escenario e impacto incluidos.
  - **Por categoría**: agrupación útil para gráficos.
  - **Metodología**: bloque de metadatos para anexar al artículo.
- `resultados.json` - datos crudos para post-procesamiento (matrices de riesgo, gráficas con matplotlib, análisis estadístico, etc.)

## Estructura del proyecto

```
passive-security-audit/
├── src/
│   └── audit.py # Script principal
├── reports/ # Salidas (se genera al ejecutar)
│   ├── reporte_seguridad.xlsx
│   └── resultados.json
├── docs/
│   └── methodology.md # Notas sobre metodología
├── requirements.txt
├── .gitignore
├── LICENSE
└── README.md
```

## Cómo se interpreta un hallazgo

Cada hallazgo tiene estos campos en el reporte:

| Campo | Significado |
|---|---|
| Sistema / URL / Fecha | Identificación del target y momento de la auditoría |
| Categoría | Módulo que generó el hallazgo (Cabeceras HTTP, Cookies, TLS, etc.) |
| Tipo de hallazgo | Clasificación específica del problema |
| Elemento | Cabecera, cookie, atributo o tag concreto observado |
| Valor observado | Lo que el servidor devolvió |
| Severidad | CRÍTICO, ALTO, MEDIO, BAJO |
| OWASP API Top 10:2023 | Categoría del marco de referencia |
| Descripción | Qué representa la debilidad en términos técnicos |
| **Vector de ataque** | Técnica concreta que un atacante podría usar (MITM, XSS, CSRF, etc.) |
| **Escenario concreto** | Narrativa paso a paso de cómo se materializa el riesgo en un caso real |
| **Impacto / Consecuencia** | Qué pierde el usuario, el sistema o la organización si el ataque tiene éxito |
| Recomendación | Cómo mitigar el problema |
| Referencia | RFC, estándar o guía OWASP que aplica |

Las tres columnas resaltadas (vector, escenario, impacto) son la principal diferencia frente a herramientas comerciales como OWASP ZAP, securityheaders.com o Mozilla Observatory: en lugar de devolver una nota numérica, este script entrega texto analítico que puede citarse directamente en un artículo de investigación.

### Ejemplo de fila del reporte

| Campo | Contenido |
|---|---|
| Tipo | Cabecera de seguridad ausente |
| Elemento | Strict-Transport-Security |
| Severidad | ALTO |
| OWASP | API8:2023 - Security Misconfiguration |
| Vector de ataque | Man-in-the-Middle (MITM) por SSL stripping |
| Escenario | Un usuario en una red WiFi pública escribe el dominio en el navegador. La primera petición sale por HTTP plano antes de redirigir a HTTPS. Un atacante en la misma red intercepta esa petición y mantiene al usuario en HTTP. Sin HSTS guardado, el navegador no protesta. |
| Impacto | Captura de credenciales en texto plano (usuario, contraseña, tokens, datos personales). El usuario no detecta el ataque. |

## Limitaciones conocidas

- Algunos servidores devuelven 403 a clientes que no parecen navegadores. El User-Agent por defecto imita a Chrome para sortear los filtros más simples, pero contra WAFs agresivos (Cloudflare, Akamai en modo estricto) las respuestas pueden no llegar.
- El análisis de TLS solo cubre el handshake estándar; no enumera cipher suites soportadas (eso requiere herramientas como `testssl.sh` o `nmap`).
- La detección de endpoints API es por patrón regex en el HTML/JS público. SPAs que cargan rutas dinámicamente desde un bundle minificado pueden esconder rutas que solo aparecen tras la ejecución del JavaScript.
- Los textos de vector/escenario/impacto están pensados para portales del sector público ecuatoriano. Si se aplica a otros contextos puede convenir adaptarlos al dominio específico.

## Marco ético y legal

Este script realiza únicamente análisis pasivo no intrusivo: solo lee respuestas HTTP estándar y archivos públicos diseñados para ser leídos. No constituye una prueba de penetración y no requiere autorización del propietario del sitio bajo la mayoría de marcos legales (Convenio de Budapest, Art. 232 COIP Ecuador, etc.).

Aun así, se recomienda:

1. Usar el script preferentemente sobre sitios propios o con autorización explícita.
2. No abusar del rate limiting (el código incluye un timeout pero no rate limiting agresivo, así que no atacar al mismo target en bucle infinito).
3. Para análisis activos (pen-testing, fuzzing, etc.) usar herramientas dedicadas y siempre con autorización por escrito.

## Cita académica

Si usas este código en investigación académica, puedes citarlo así:

```
Ing. Rubén Borja U., MSc. (2026) Auditor pasivo de seguridad web bajo el marco
OWASP API Security Top 10:2023 [Software]. GitHub.
https://github.com/rubenborja/passive-security-audit
```

## Licencia

MIT - ver [LICENSE](LICENSE).

## Contribuir

Pull requests bienvenidas. Si encuentras un nuevo patrón de hallazgo que valga la pena agregar al catálogo, abrir un issue describiendo:

1. Qué cabecera/atributo/elemento detectar
2. Por qué es un riesgo (con referencia a OWASP/RFC/CVE si aplica)
3. Vector de ataque, escenario concreto e impacto esperado
4. Cómo mitigarlo