"""
Auditor pasivo de seguridad web
-------------------------------

Marco de referencia: OWASP API Security Top 10:2023
Tipo de análisis: pasivo, no intrusivo

Este script revisa portales web públicos y reporta debilidades de seguridad
detectables sin atacar el sistema. Solo inspecciona respuestas del servidor,
código fuente público y archivos de metadatos estandarizados (robots.txt,
sitemap.xml, security.txt). No inyecta payloads, no prueba credenciales,
no fuerza ningún recurso oculto.

La idea es que cualquiera pueda reproducir los hallazgos con un navegador
y curl. Lo único que hace este script es automatizar y categorizar eso bajo
el marco OWASP API Security Top 10:2023.

Uso: python src/audit.py

Salida (carpeta reports/):
reporte_seguridad.xlsx (reporte con varias hojas)
resultados.json (datos crudos para post-procesamiento)
"""

import json
import os
import re
import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse

import requests
import pandas as pd
from bs4 import BeautifulSoup, Comment
import urllib3

# Las advertencias de SSL las silencio porque algunos portales públicos tienen
# cadenas de certificados raras que ensucian el log. El verify=False solo se
# usa para que el script no muera ante un cert auto-firmado, pero igual
# reportamos esa condición como hallazgo.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# Configuración
# -------------

# Edita esta lista con los sitios que quieras auditar. Conviene usar las URLs
# reales de las páginas que ve un usuario, no la raíz del dominio: las
# cabeceras pueden cambiar entre rutas.
TARGETS = [
    {
        "nombre": "SRI - Servicios en Línea",
        "url": "https://srienlinea.sri.gob.ec/sri-en-linea/inicio/NAT",
    },
    {
        "nombre": "Registro Civil en Línea",
        "url": "https://apps.registrocivil.gob.ec/portalCiudadano/login.jsf",
    },
    {
        "nombre": "SERCOP - Sistema Oficial de Contratación Pública",
        "url": "https://www.compraspublicas.gob.ec/ProcesoContratacion/compras/",
    },
    {
        "nombre": "IESS - Afiliados",
        "url": "https://app.iess.gob.ec/gestion-afiliado-web/app/index",
    },
    {
        "nombre": "Ministerio de Educación",
        "url": "https://educacion.gob.ec/",
    },
    {
        "nombre": "SENESCYT - Consulta de Títulos",
        "url": "https://www.senescyt.gob.ec/web/guest/consultas",
    },
    {
        "nombre": "ANT - Consulta de Licencias y Citaciones",
        "url": "https://consultaweb.ant.gob.ec/PortalWEB/paginas/clientes/clp_criterio_consulta.jsp",
    },
    {
        "nombre": "ANT - Sistema Virtual de Turnos",
        "url": "https://consultaweb.ant.gob.ec/SVT/paginas/portal/svf_solicitar_servicio.jsp",
    },
    {
        "nombre": "CNE - Consulta de Lugar de Votación",
        "url": "https://lugarvotacion.cne.gob.ec/",
    }
]

CARPETA_REPORTES = "reports"
TIMEOUT = 20  # segundos por request; algunos portales detrás de CDNs son lentos

# User-Agent realista. Muchos portales bloquean User-Agents tipo "python-requests"
# devolviendo 403 sin siquiera adjuntar las cabeceras de seguridad. Con un UA
# de navegador normal el comportamiento es más representativo.
USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

HEADERS_DEFAULT = {
    "User-Agent": USER_AGENT,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "es-EC,es;q=0.9,en;q=0.8",
}


# Catálogo de cabeceras de seguridad
# ----------------------------------
# Cada entrada mapea una cabecera al riesgo OWASP correspondiente. La idea es
# que el reporte no diga solo "falta tal cabecera", sino que clasifique el
# hallazgo en una categoría reconocible y explique qué puede ocasionar
# (escenario concreto + impacto). Eso es lo que pide la revisión académica.
#
# Ampliar el catálogo es solo agregar una entrada nueva al diccionario,
# sin tocar la lógica del script.

CABECERAS_OBLIGATORIAS = {
    "Strict-Transport-Security": {
        "descripcion": "Obliga al navegador a usar siempre HTTPS para este dominio",
        "owasp": "API8:2023 - Security Misconfiguration",
        "severidad": "ALTO",
        "recomendacion": "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        "referencia": "RFC 6797",
        "vector_ataque": "Man-in-the-Middle (MITM) por SSL stripping",
        "escenario": "Un usuario en una red WiFi pública escribe el dominio en el navegador. La primera petición sale por HTTP plano antes de redirigir a HTTPS. Un atacante en la misma red intercepta esa petición y mantiene al usuario en HTTP. Sin HSTS guardado, el navegador no protesta.",
        "impacto": "Captura de credenciales en texto plano (usuario, contraseña, tokens, datos personales). El usuario no detecta el ataque.",
    },
    "Content-Security-Policy": {
        "descripcion": "Define qué orígenes pueden cargar scripts, estilos e imágenes",
        "owasp": "API8:2023 - Security Misconfiguration",
        "severidad": "ALTO",
        "recomendacion": "Empezar con default-src 'self' y abrir solo lo necesario",
        "referencia": "W3C CSP Level 3",
        "vector_ataque": "Cross-Site Scripting (XSS) sin contención",
        "escenario": "Si un atacante encuentra un punto de inyección de HTML/JavaScript (campo de búsqueda, parámetro reflejado, comentario mal saneado), puede inyectar código que el navegador ejecuta sin restricciones de origen.",
        "impacto": "Robo de tokens de sesión, redirección a sitios falsos, modificación del DOM visible para la víctima, ejecución de keyloggers en el navegador.",
    },
    "X-Content-Type-Options": {
        "descripcion": "Bloquea MIME-sniffing del navegador",
        "owasp": "API8:2023 - Security Misconfiguration",
        "severidad": "MEDIO",
        "recomendacion": "X-Content-Type-Options: nosniff",
        "referencia": "Microsoft / WHATWG",
        "vector_ataque": "MIME sniffing attack",
        "escenario": "Un atacante sube un archivo aparentemente inofensivo (una imagen .jpg) que contiene JavaScript en su interior. Sin nosniff, el navegador adivina el tipo real del archivo y termina ejecutándolo como script.",
        "impacto": "Ejecución de código JavaScript desde archivos subidos al servidor. Encadenamiento con XSS persistente.",
    },
    "X-Frame-Options": {
        "descripcion": "Evita que el sitio se cargue dentro de un iframe ajeno (clickjacking)",
        "owasp": "API8:2023 - Security Misconfiguration",
        "severidad": "MEDIO",
        "recomendacion": "X-Frame-Options: DENY (o usar frame-ancestors en CSP)",
        "referencia": "RFC 7034",
        "vector_ataque": "Clickjacking (UI redressing)",
        "escenario": "El atacante crea un sitio malicioso que carga el portal real dentro de un iframe invisible, encima de botones falsos. La víctima cree que hace clic en un botón inocente pero realmente autoriza acciones en el portal autenticado.",
        "impacto": "Acciones autenticadas ejecutadas sin consentimiento del usuario: transacciones, cambios de datos personales, autorizaciones financieras.",
    },
    "Referrer-Policy": {
        "descripcion": "Controla qué información se envía en la cabecera Referer",
        "owasp": "API8:2023 - Security Misconfiguration",
        "severidad": "BAJO",
        "recomendacion": "Referrer-Policy: strict-origin-when-cross-origin",
        "referencia": "W3C Referrer Policy",
        "vector_ataque": "Filtración de información en cabecera Referer",
        "escenario": "Cuando el usuario hace clic en un enlace externo desde el portal, el navegador envía la URL completa de origen al sitio destino, incluyendo parámetros que pueden contener tokens, números de cédula u otros identificadores.",
        "impacto": "Filtración pasiva de identificadores y tokens hacia terceros (analytics, anuncios, sitios externos que registran los Referers en sus access logs).",
    },
    "Permissions-Policy": {
        "descripcion": "Controla qué APIs del navegador puede usar el sitio",
        "owasp": "API8:2023 - Security Misconfiguration",
        "severidad": "BAJO",
        "recomendacion": "Permissions-Policy: geolocation=(), camera=(), microphone=()",
        "referencia": "W3C Permissions Policy",
        "vector_ataque": "Abuso de APIs del navegador",
        "escenario": "Si un atacante logra inyectar código (vía XSS o iframe), puede activar la cámara, micrófono, geolocalización o portapapeles del usuario sin restricciones explícitas declaradas por el sitio.",
        "impacto": "Espionaje activo: grabación de audio/video, captura de coordenadas GPS, lectura del portapapeles (donde se copian contraseñas con frecuencia).",
    },
    "Cross-Origin-Opener-Policy": {
        "descripcion": "Aísla el contexto de navegación de otros orígenes",
        "owasp": "API8:2023 - Security Misconfiguration",
        "severidad": "MEDIO",
        "recomendacion": "Cross-Origin-Opener-Policy: same-origin",
        "referencia": "WHATWG HTML",
        "vector_ataque": "Cross-window attacks (Spectre side-channels)",
        "escenario": "Una pestaña maliciosa abierta por la víctima puede acceder al objeto window del portal autenticado y leer datos cruzados entre orígenes mediante ataques de canal lateral basados en CPU.",
        "impacto": "Filtración de datos sensibles entre pestañas del navegador, especialmente crítico en sistemas con información tributaria o financiera.",
    },
    "Cross-Origin-Resource-Policy": {
        "descripcion": "Evita que otros orígenes embedan recursos sensibles del sitio",
        "owasp": "API8:2023 - Security Misconfiguration",
        "severidad": "BAJO",
        "recomendacion": "Cross-Origin-Resource-Policy: same-origin",
        "referencia": "Fetch Standard",
        "vector_ataque": "Spectre / cross-origin resource read",
        "escenario": "Recursos sensibles servidos por el portal (PDFs, imágenes con datos, JSONs) pueden ser embebidos por sitios maliciosos para ejecutar ataques de canal lateral basados en CPU.",
        "impacto": "Lectura cruzada de datos entre orígenes, especialmente relevante para documentos tributarios o reportes con información personal.",
    },
    "Cache-Control": {
        "descripcion": "Define cómo el navegador y proxies almacenan la respuesta",
        "owasp": "API3:2023 - Broken Object Property Level Authorization",
        "severidad": "MEDIO",
        "recomendacion": "Para páginas con datos sensibles: Cache-Control: no-store",
        "referencia": "RFC 7234",
        "vector_ataque": "Cache poisoning / fuga de datos sensibles",
        "escenario": "El navegador o un proxy intermedio (oficina, ISP, cibercafé) guarda en caché páginas con información personal del usuario. Otro usuario que acceda al mismo equipo o pase por el mismo proxy puede ver los datos del primero.",
        "impacto": "Exposición no autorizada de datos personales en equipos compartidos, cibercafés, redes corporativas con proxies caching.",
    },
}

# Estas cabeceras NO deberían estar presentes: revelan información técnica que
# ayuda al atacante a buscar exploits dirigidos. Si un servidor anuncia
# "Apache/2.4.29", el atacante va directo a buscar CVEs de esa versión.
CABECERAS_QUE_FILTRAN = {
    "Server": {
        "descripcion": "Revela el software y a veces la versión del servidor web",
        "owasp": "API8:2023 - Security Misconfiguration",
        "severidad": "MEDIO",
        "vector_ataque": "Reconocimiento dirigido (fingerprinting)",
        "escenario": "El atacante lee la cabecera Server, identifica versión exacta (ej: 'Apache/2.4.29') y consulta bases de CVEs públicas para esa versión. Si hay un exploit conocido sin parchear, lo usa directamente.",
        "impacto": "Reduce el tiempo de explotación; el atacante no enumera vulnerabilidades a ciegas, va directo a las que aplican al stack expuesto.",
    },
    "X-Powered-By": {
        "descripcion": "Revela el lenguaje o framework de backend (PHP, Express, etc.)",
        "owasp": "API8:2023 - Security Misconfiguration",
        "severidad": "MEDIO",
        "vector_ataque": "Reconocimiento dirigido (fingerprinting)",
        "escenario": "Cabeceras como 'X-Powered-By: PHP/5.6.40' confirman lenguaje y versión. El atacante busca CVEs específicos de esa versión y prepara payloads adaptados al runtime.",
        "impacto": "Permite ataques específicos al stack en lugar de exploración a ciegas. PHP 5.x sin soporte desde 2018 es un blanco frecuente.",
    },
    "X-AspNet-Version": {
        "descripcion": "Revela la versión exacta de ASP.NET",
        "owasp": "API8:2023 - Security Misconfiguration",
        "severidad": "ALTO",
        "vector_ataque": "Explotación dirigida a versión específica",
        "escenario": "Conocer versión exacta de ASP.NET permite al atacante identificar vectores como deserialización insegura (ViewState), Padding Oracle (CVE-2010-3332) o exploits de WCF, según corresponda a la versión.",
        "impacto": "Acceso a CVEs históricos no parcheados; ASP.NET tiene historial de vulnerabilidades críticas en versiones antiguas.",
    },
    "X-AspNetMvc-Version": {
        "descripcion": "Revela la versión exacta de ASP.NET MVC",
        "owasp": "API8:2023 - Security Misconfiguration",
        "severidad": "ALTO",
        "vector_ataque": "Explotación dirigida al framework MVC",
        "escenario": "Conocer la versión de MVC permite identificar fallos específicos del framework: bypasses de validación de modelos, problemas conocidos de routing, o exploits sobre helpers vulnerables.",
        "impacto": "Permite ataques específicos al framework MVC sin necesidad de probar exploits genéricos.",
    },
    "X-Generator": {
        "descripcion": "Revela el CMS o generador (Drupal, Joomla, etc.)",
        "owasp": "API8:2023 - Security Misconfiguration",
        "severidad": "BAJO",
        "vector_ataque": "Identificación de CMS para ataques específicos",
        "escenario": "Saber que el sitio corre en Drupal 7 o WordPress 5.x permite buscar exploits públicos de plugins, temas y core (Drupalgeddon, Pwnpress, etc.).",
        "impacto": "Acceso a kits de exploits específicos del CMS detectado, muchos de ellos automatizados.",
    },
    "X-Drupal-Cache": {
        "descripcion": "Confirma que el sitio corre en Drupal",
        "owasp": "API8:2023 - Security Misconfiguration",
        "severidad": "BAJO",
        "vector_ataque": "Identificación de CMS Drupal",
        "escenario": "Confirmar Drupal permite al atacante usar herramientas como droopescan o consultar la lista de exploits de Drupal específicos a la rama (Drupalgeddon, etc.).",
        "impacto": "Aumenta la superficie de ataque dirigida al CMS, especialmente si la versión está sin parches.",
    },
    "X-Backend-Server": {
        "descripcion": "Revela hostname interno del backend",
        "owasp": "API8:2023 - Security Misconfiguration",
        "severidad": "MEDIO",
        "vector_ataque": "Mapeo de infraestructura interna",
        "escenario": "Cabeceras como 'X-Backend-Server: app01.internal.gov.ec' exponen nomenclatura interna y a veces patrones IP. Combinado con DNS rebinding o SSRF puede dar acceso directo a la red interna.",
        "impacto": "Revela arquitectura interna; facilita ataques de pivoting, DNS rebinding y SSRF dirigidos.",
    },
    "X-Runtime": {
        "descripcion": "Tiempo de respuesta interno; típico de Rails / Phoenix",
        "owasp": "API8:2023 - Security Misconfiguration",
        "severidad": "BAJO",
        "vector_ataque": "Identificación del framework + ataques de tiempo",
        "escenario": "Confirma uso de Rails o Phoenix. Además, los tiempos de respuesta exactos pueden usarse para ataques de tiempo en autenticación (timing attacks sobre hashes).",
        "impacto": "Confirmación del stack y posible vector para timing attacks en endpoints de autenticación.",
    },
    "Via": {
        "descripcion": "Expone proxies intermedios y a veces sus versiones",
        "owasp": "API8:2023 - Security Misconfiguration",
        "severidad": "BAJO",
        "vector_ataque": "Mapeo de cadena de proxies",
        "escenario": "La cabecera Via lista los proxies por los que pasó la respuesta, incluyendo versiones (ej: 'Via: 1.1 squid/3.5.27'). Eso revela arquitectura de red y puede habilitar ataques de cache poisoning si el proxy es vulnerable.",
        "impacto": "Exposición de la topología de red; identificación de proxies con CVEs conocidos para cache poisoning o request smuggling.",
    },
}


# Helpers de presentación en consola
# ----------------------------------

def banner(texto):
    """Encabezado visible para separar bloques en consola."""
    linea = "─" * 70
    print(f"\n{linea}\n  {texto}\n{linea}")


def seccion(texto):
    """Encabezado de segundo nivel, para subsecciones dentro de un análisis."""
    print(f"\n  >> {texto}")


def hallazgo_print(severidad, texto):
    """Imprime un hallazgo con icono según severidad. Solo cosmético."""
    iconos = {
        "CRITICO": "[!!]",
        "ALTO": "[!]",
        "MEDIO": "[*]",
        "BAJO": "[i]",
        "INFO": "[.]",
        "OK": "[+]",
    }
    print(f"     {iconos.get(severidad, '[?]')} [{severidad:<7}] {texto}")


# Módulo 1 - Cabeceras HTTP
# -------------------------

def analizar_cabeceras_http(url, response):
    """Revisa las cabeceras de respuesta HTTP y devuelve la lista de hallazgos.

    No reinventa la rueda: la lista a verificar viene de los diccionarios
    CABECERAS_OBLIGATORIAS y CABECERAS_QUE_FILTRAN. Eso permite ampliar el
    catálogo solo agregando entradas, sin tocar la lógica.
    """
    hallazgos = []

    # Las cabeceras HTTP son case-insensitive según RFC 7230, pero los
    # servidores las devuelven en cualquier formato. Normalizo a minúsculas
    # para comparar de forma confiable.
    headers_norm = {k.lower(): v for k, v in response.headers.items()}

    seccion("Cabeceras de seguridad obligatorias")
    for nombre_header, info in CABECERAS_OBLIGATORIAS.items():
        if nombre_header.lower() in headers_norm:
            hallazgo_print("OK", f"Presente: {nombre_header}")
        else:
            hallazgo_print(info["severidad"],
                           f"FALTA {nombre_header} - {info['descripcion']}")
            hallazgos.append({
                "categoria": "Cabeceras HTTP",
                "tipo": "Cabecera de seguridad ausente",
                "elemento": nombre_header,
                "valor_observado": "(no presente)",
                "severidad": info["severidad"],
                "owasp": info["owasp"],
                "descripcion": info["descripcion"],
                "vector_ataque": info["vector_ataque"],
                "escenario": info["escenario"],
                "impacto": info["impacto"],
                "recomendacion": info["recomendacion"],
                "referencia": info["referencia"],
            })

    seccion("Cabeceras que pueden filtrar información del stack")
    for nombre_header, info in CABECERAS_QUE_FILTRAN.items():
        if nombre_header.lower() in headers_norm:
            valor = headers_norm[nombre_header.lower()]
            hallazgo_print(info["severidad"],
                           f"EXPONE {nombre_header}: {valor}")
            hallazgos.append({
                "categoria": "Cabeceras HTTP",
                "tipo": "Filtración de información",
                "elemento": nombre_header,
                "valor_observado": valor,
                "severidad": info["severidad"],
                "owasp": info["owasp"],
                "descripcion": info["descripcion"],
                "vector_ataque": info["vector_ataque"],
                "escenario": info["escenario"],
                "impacto": info["impacto"],
                "recomendacion": f"Suprimir o redactar la cabecera {nombre_header} en la configuración del servidor",
                "referencia": "OWASP ASVS V14.4",
            })

    return hallazgos


# Módulo 2 - Cookies
# ------------------

def analizar_cookies(url, response):
    """Verifica las flags de seguridad de cada cookie.

    Las tres flags importantes son Secure, HttpOnly y SameSite. Sin Secure,
    la cookie viaja por HTTP plano si el usuario aterriza por error en una
    URL no cifrada. Sin HttpOnly, JavaScript puede leerla (un boleto directo
    a robo de sesión vía XSS). Sin SameSite, queda expuesta a CSRF.
    """
    hallazgos = []
    seccion("Análisis de cookies")

    if not response.cookies:
        hallazgo_print("INFO", "El servidor no envió cookies en esta respuesta")
        return hallazgos

    # response.cookies devuelve un RequestsCookieJar que pierde algunos
    # atributos. Para revisar las flags toca parsear la cabecera Set-Cookie
    # cruda.
    raw_cookies = response.headers.get("Set-Cookie", "")
    if not raw_cookies:
        raw_cookies_list = (response.raw.headers.getlist("Set-Cookie")
                            if hasattr(response.raw, "headers") else [])
        raw_cookies = "\n".join(raw_cookies_list)

    nombres_reveladores = {
        "PHPSESSID": "PHP",
        "JSESSIONID": "Java (Tomcat/JBoss/etc.)",
        "ASP.NET_SessionId": "ASP.NET",
        "ASPSESSIONID": "Classic ASP",
        "CFID": "ColdFusion",
        "CFTOKEN": "ColdFusion",
        "laravel_session": "Laravel (PHP)",
        "_rails_session": "Ruby on Rails",
        "connect.sid": "Express.js / Node",
    }

    for cookie in response.cookies:
        nombre = cookie.name
        problemas = []

        bloque = ""
        for linea in raw_cookies.split("\n"):
            if nombre in linea:
                bloque = linea.lower()
                break

        if "secure" not in bloque:
            problemas.append("falta flag Secure")
        if "httponly" not in bloque:
            problemas.append("falta flag HttpOnly")
        if "samesite" not in bloque:
            problemas.append("falta atributo SameSite")

        if nombre in nombres_reveladores:
            tecnologia = nombres_reveladores[nombre]
            hallazgo_print("BAJO",
                           f"Cookie '{nombre}' delata uso de {tecnologia}")
            hallazgos.append({
                "categoria": "Cookies",
                "tipo": "Filtración de stack vía nombre de cookie",
                "elemento": nombre,
                "valor_observado": tecnologia,
                "severidad": "BAJO",
                "owasp": "API8:2023 - Security Misconfiguration",
                "descripcion": f"El nombre de la cookie revela que el backend corre sobre {tecnologia}",
                "vector_ataque": "Reconocimiento del stack tecnológico",
                "escenario": f"El atacante observa la cookie '{nombre}' en cualquier respuesta y deduce que el backend usa {tecnologia}. Combina ese dato con otras pistas (cabeceras, rutas) para identificar la versión exacta y buscar exploits.",
                "impacto": f"Reduce el espacio de búsqueda del atacante; puede ir directo a CVEs conocidos de {tecnologia} sin enumerar a ciegas.",
                "recomendacion": "Renombrar la cookie de sesión para no anunciar el stack",
                "referencia": "OWASP Cheat Sheet: Session Management",
            })

        if problemas:
            severidad = "ALTO" if ("falta flag Secure" in problemas
                                   or "falta flag HttpOnly" in problemas) else "MEDIO"
            descripcion = f"Cookie '{nombre}' con flags incompletas: {', '.join(problemas)}"
            hallazgo_print(severidad, descripcion)

            # El vector y el impacto cambian según qué flag falta. Personalizo
            # el mensaje para que el reporte sea preciso, no genérico.
            if "falta flag Secure" in problemas:
                vector = "Captura de cookie por canal HTTP no cifrado"
                escenario = ("Si el usuario navega por error a la versión HTTP del sitio (escribiendo el dominio sin https://, o por un enlace antiguo), la cookie viajará en texto plano. Un atacante en la misma red WiFi la captura con un sniffer.")
                impacto = "Robo de la sesión activa del usuario; el atacante usa la cookie para hacerse pasar por la víctima sin necesidad de su contraseña."
            elif "falta flag HttpOnly" in problemas:
                vector = "Robo de cookie vía JavaScript (XSS)"
                escenario = "Si el sitio tiene cualquier vulnerabilidad de XSS, el JavaScript inyectado puede leer document.cookie y enviarlo a un servidor del atacante. Sin HttpOnly, esto es trivial."
                impacto = "Convierte cualquier XSS en robo directo de sesión; eleva la severidad de toda XSS posterior de Media a Crítica."
            else:
                vector = "Cross-Site Request Forgery (CSRF)"
                escenario = "Sin SameSite, el navegador envía la cookie de sesión cuando un sitio externo dispara una petición al portal (vía formulario o fetch). El atacante puede ejecutar acciones autenticadas desde su propio sitio."
                impacto = "Acciones autenticadas ejecutadas sin consentimiento del usuario, similar al impacto de clickjacking pero a nivel de petición HTTP."

            hallazgos.append({
                "categoria": "Cookies",
                "tipo": "Cookie con flags de seguridad incompletas",
                "elemento": nombre,
                "valor_observado": ", ".join(problemas),
                "severidad": severidad,
                "owasp": "API2:2023 - Broken Authentication",
                "descripcion": descripcion,
                "vector_ataque": vector,
                "escenario": escenario,
                "impacto": impacto,
                "recomendacion": "Set-Cookie: name=value; Secure; HttpOnly; SameSite=Strict",
                "referencia": "RFC 6265bis",
            })
        else:
            hallazgo_print("OK", f"Cookie '{nombre}' tiene Secure + HttpOnly + SameSite")

    return hallazgos


# Módulo 3 - CORS
# ---------------

def analizar_cors(url, response):
    """Detecta políticas CORS demasiado permisivas.

    El caso clásico: 'Access-Control-Allow-Origin: *' junto con
    'Access-Control-Allow-Credentials: true'. Esa combinación efectivamente
    desactiva la same-origin policy, permitiendo que cualquier sitio lea
    respuestas autenticadas. Es uno de los errores más comunes en APIs nuevas
    que sus desarrolladores configuraron "para que funcione" y nunca volvieron
    a tocar.
    """
    hallazgos = []
    seccion("Análisis de política CORS")

    headers_norm = {k.lower(): v for k, v in response.headers.items()}
    origen_permitido = headers_norm.get("access-control-allow-origin")
    credenciales = headers_norm.get("access-control-allow-credentials")

    if origen_permitido is None:
        hallazgo_print("INFO", "No se observan cabeceras CORS en esta respuesta")
        return hallazgos

    if origen_permitido == "*":
        if credenciales and credenciales.lower() == "true":
            # Esta es la combinación peligrosa. Los navegadores bloquean esto
            # en la práctica, pero algunos endpoints aún lo intentan.
            hallazgo_print("CRITICO",
                           "CORS abierto a cualquier origen con credenciales habilitadas")
            hallazgos.append({
                "categoria": "CORS",
                "tipo": "Política CORS peligrosa",
                "elemento": "Access-Control-Allow-Origin",
                "valor_observado": "Origin=*, Credentials=true",
                "severidad": "CRITICO",
                "owasp": "API8:2023 - Security Misconfiguration",
                "descripcion": "El servidor acepta cualquier origen Y permite credenciales",
                "vector_ataque": "Cross-Origin data exfiltration",
                "escenario": "El atacante crea un sitio malicioso. Cuando la víctima autenticada lo visita, el sitio hace fetch() a la API del portal con credentials='include'. Como el servidor responde con Allow-Origin:* y Allow-Credentials:true, el navegador entrega la respuesta autenticada al atacante.",
                "impacto": "Lectura completa de cualquier dato que la API exponga al usuario autenticado: información personal, financiera, tributaria. Equivalente a un robo silencioso de sesión.",
                "recomendacion": "Listar orígenes específicos en lugar de '*' cuando hay credenciales",
                "referencia": "Fetch Standard - CORS protocol",
            })
        else:
            hallazgo_print("MEDIO", "CORS abierto a todos los orígenes ('*')")
            hallazgos.append({
                "categoria": "CORS",
                "tipo": "Política CORS demasiado permisiva",
                "elemento": "Access-Control-Allow-Origin",
                "valor_observado": "*",
                "severidad": "MEDIO",
                "owasp": "API8:2023 - Security Misconfiguration",
                "descripcion": "Cualquier sitio web puede leer respuestas de esta API desde un navegador",
                "vector_ataque": "Cross-Origin data scraping",
                "escenario": "Sitios externos pueden hacer fetch() a esta API y leer respuestas no autenticadas, lo que facilita scraping masivo, agregación no autorizada de datos públicos, o uso de la API en aplicaciones de terceros sin autorización.",
                "impacto": "Pérdida de control sobre quién consume la API; posible saturación por consumidores no autorizados; uso indebido de datos en aplicaciones derivadas.",
                "recomendacion": "Restringir orígenes a una lista blanca específica",
                "referencia": "OWASP CORS OriginHeaderScrutiny",
            })
    else:
        hallazgo_print("OK", f"CORS configurado: {origen_permitido}")

    return hallazgos


# Módulo 4 - TLS / SSL
# --------------------

def analizar_tls(url):
    """Hace un handshake TLS y reporta sobre el certificado y la versión del protocolo.

    Esto se considera análisis pasivo porque no envía datos de aplicación,
    solo el handshake estándar que cualquier navegador haría al cargar la
    página.
    """
    hallazgos = []
    seccion("Análisis de TLS / Certificado")

    parsed = urlparse(url)
    if parsed.scheme != "https":
        hallazgo_print("CRITICO", "El sitio no usa HTTPS")
        hallazgos.append({
            "categoria": "TLS",
            "tipo": "Sitio sin cifrado",
            "elemento": "Esquema de URL",
            "valor_observado": parsed.scheme,
            "severidad": "CRITICO",
            "owasp": "API8:2023 - Security Misconfiguration",
            "descripcion": "El tráfico viaja en texto plano",
            "vector_ataque": "Eavesdropping pasivo en cualquier salto de red",
            "escenario": "Cualquier intermediario en la ruta de red (ISP, proxy corporativo, atacante en WiFi pública) puede leer todo el tráfico: credenciales, datos personales, tokens de sesión, contenido completo de las respuestas.",
            "impacto": "Compromiso total de confidencialidad e integridad. Cualquier interacción con el sitio es interceptable y modificable por terceros.",
            "recomendacion": "Forzar HTTPS y redirigir HTTP a HTTPS con HSTS",
            "referencia": "RFC 8446 (TLS 1.3)",
        })
        return hallazgos

    host = parsed.hostname
    port = parsed.port or 443

    try:
        contexto = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            with contexto.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                version_tls = ssock.version()
                cipher = ssock.cipher()

        hallazgo_print("INFO", f"TLS negociado: {version_tls}")
        hallazgo_print("INFO", f"Cipher suite: {cipher[0] if cipher else 'desconocido'}")

        # TLS 1.0 y 1.1 están deprecados desde 2020 (RFC 8996). Si el handshake
        # los negocia, el servidor todavía los acepta y eso es un riesgo.
        if version_tls in ("TLSv1", "TLSv1.1"):
            hallazgo_print("ALTO", f"Versión TLS deprecada: {version_tls}")
            hallazgos.append({
                "categoria": "TLS",
                "tipo": "Versión de TLS obsoleta",
                "elemento": "Protocolo",
                "valor_observado": version_tls,
                "severidad": "ALTO",
                "owasp": "API8:2023 - Security Misconfiguration",
                "descripcion": f"{version_tls} fue oficialmente deprecado en 2020 (RFC 8996)",
                "vector_ataque": "Ataques criptográficos sobre cifrados débiles",
                "escenario": f"{version_tls} tiene vulnerabilidades conocidas como BEAST (CVE-2011-3389) y POODLE (CVE-2014-3566). Un atacante MITM puede forzar al cliente a negociar la versión débil y aprovechar estos ataques para descifrar el tráfico.",
                "impacto": "Compromiso de la confidencialidad del canal cifrado; el atacante puede leer tráfico que el usuario cree seguro.",
                "recomendacion": "Permitir solo TLS 1.2 y 1.3",
                "referencia": "RFC 8996",
            })

        if cert:
            # cert['notAfter'] viene como string 'Mmm dd HH:MM:SS YYYY GMT'
            try:
                fecha_expira = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                # datetime.utcnow() está deprecado en Python 3.12+. Uso .now()
                # simple porque la fecha del cert ya está en GMT.
                dias_restantes = (fecha_expira - datetime.now()).days

                if dias_restantes < 0:
                    hallazgo_print("CRITICO",
                                   f"Certificado EXPIRADO hace {abs(dias_restantes)} días")
                    hallazgos.append({
                        "categoria": "TLS",
                        "tipo": "Certificado expirado",
                        "elemento": "notAfter",
                        "valor_observado": cert["notAfter"],
                        "severidad": "CRITICO",
                        "owasp": "API8:2023 - Security Misconfiguration",
                        "descripcion": "El certificado del servidor venció",
                        "vector_ataque": "Bypass de validación + degradación de confianza",
                        "escenario": "Los navegadores muestran advertencia roja crítica que el usuario puede ignorar (clic en 'Continuar de todos modos'). Eso entrena al usuario a saltarse advertencias futuras, abriendo la puerta a ataques MITM con certificados auto-firmados que el usuario también ignorará.",
                        "impacto": "Pérdida total de disponibilidad para usuarios cuidadosos; entrenamiento de bypass de advertencias en usuarios menos cuidadosos.",
                        "recomendacion": "Renovar el certificado de inmediato",
                        "referencia": "RFC 5280",
                    })
                elif dias_restantes < 30:
                    hallazgo_print("MEDIO",
                                   f"Certificado expira en {dias_restantes} días")
                    hallazgos.append({
                        "categoria": "TLS",
                        "tipo": "Certificado próximo a expirar",
                        "elemento": "notAfter",
                        "valor_observado": cert["notAfter"],
                        "severidad": "MEDIO",
                        "owasp": "API8:2023 - Security Misconfiguration",
                        "descripcion": f"El certificado expira en {dias_restantes} días",
                        "vector_ataque": "Riesgo de interrupción de servicio",
                        "escenario": f"Si el certificado caduca antes de renovarse (en {dias_restantes} días), todos los navegadores mostrarán error crítico. Los usuarios pierden acceso al portal hasta la renovación.",
                        "impacto": "Indisponibilidad del servicio; daño reputacional; pérdida de transacciones durante la ventana de caducidad.",
                        "recomendacion": "Programar renovación automática (Let's Encrypt o ACME)",
                        "referencia": "Mozilla Server Side TLS Guidelines",
                    })
                else:
                    hallazgo_print("OK",
                                   f"Certificado vigente ({dias_restantes} días restantes)")
            except ValueError:
                hallazgo_print("INFO", "No se pudo parsear la fecha de expiración")

            issuer = dict(x[0] for x in cert.get("issuer", []))
            hallazgo_print("INFO",
                           f"Emisor: {issuer.get('organizationName', 'desconocido')}")

    except ssl.SSLError as e:
        hallazgo_print("ALTO", f"Error TLS: {e}")
        hallazgos.append({
            "categoria": "TLS",
            "tipo": "Error de handshake TLS",
            "elemento": "Conexión",
            "valor_observado": str(e),
            "severidad": "ALTO",
            "owasp": "API8:2023 - Security Misconfiguration",
            "descripcion": f"El servidor falló el handshake TLS: {e}",
            "vector_ataque": "Configuración TLS rota o cadena de certificados inválida",
            "escenario": "El handshake falla por cadena incompleta, certificado auto-firmado, o suite de cifrado incompatible. Los usuarios reciben advertencia de seguridad y muchos terminan ignorándola.",
            "impacto": "Pérdida de usuarios cuidadosos; posibilidad de ataques MITM con certificados falsos si los usuarios se acostumbran a ignorar advertencias.",
            "recomendacion": "Revisar configuración de TLS y cadena de certificados",
            "referencia": "RFC 8446",
        })
    except Exception as e:
        hallazgo_print("INFO", f"No se pudo completar análisis TLS: {e}")

    return hallazgos


# Módulo 5 - HTML público
# -----------------------

def analizar_html(url, response):
    """Revisa el HTML que el servidor envía a cualquier visitante.

    Aquí se buscan: comentarios HTML que dejen pistas (TODOs, credenciales,
    rutas internas), meta tag generator (revela CMS), formularios sin HTTPS
    o con autocomplete habilitado en passwords, recursos externos cargados
    por HTTP (mixed content), y endpoints de API referenciados desde el JS.

    Es lo mismo que cualquiera ve haciendo Ctrl+U en el navegador. Por eso
    es 100% pasivo.
    """
    hallazgos = []
    seccion("Análisis del HTML público")

    try:
        soup = BeautifulSoup(response.text, "html.parser")
    except Exception as e:
        hallazgo_print("INFO", f"No se pudo parsear el HTML: {e}")
        return hallazgos

    # Meta tag "generator": el CMS lo deja por defecto y delata la plataforma.
    # Es trivial removerlo y casi nadie lo hace.
    generator = soup.find("meta", attrs={"name": "generator"})
    if generator and generator.get("content"):
        contenido = generator["content"]
        hallazgo_print("BAJO", f"Meta generator expuesto: {contenido}")
        hallazgos.append({
            "categoria": "HTML",
            "tipo": "Meta tag generator expone tecnología",
            "elemento": "<meta name='generator'>",
            "valor_observado": contenido,
            "severidad": "BAJO",
            "owasp": "API8:2023 - Security Misconfiguration",
            "descripcion": "El meta generator delata el CMS o framework usado",
            "vector_ataque": "Reconocimiento de CMS para ataques específicos",
            "escenario": f"El atacante lee el meta generator y obtiene '{contenido}'. Con esa información busca exploits públicos del CMS y su versión, plugins vulnerables conocidos, y configuraciones por defecto a probar.",
            "impacto": "Reduce el tiempo de reconocimiento del atacante; permite ataques dirigidos en lugar de exploración a ciegas.",
            "recomendacion": "Remover el meta tag o sobrescribirlo con valor genérico",
            "referencia": "OWASP Testing Guide - Information Gathering",
        })

    # Comentarios HTML sospechosos. Los <!-- --> a veces contienen TODOs,
    # rutas internas, nombres de devs o incluso credenciales olvidadas. He
    # visto de todo en producción.
    patrones_sospechosos = [
        (r"todo[:\s]", "TODO"),
        (r"fixme", "FIXME"),
        (r"hack", "HACK"),
        (r"password\s*[=:]", "posible credencial"),
        (r"api[_-]?key", "posible API key"),
        (r"localhost", "referencia a localhost"),
        (r"127\.0\.0\.1", "referencia a localhost"),
        (r"192\.168\.", "referencia a IP interna"),
        (r"10\.\d+\.", "referencia a IP interna"),
    ]
    comentarios_reales = soup.find_all(string=lambda text: isinstance(text, Comment))

    for comentario in comentarios_reales:
        texto_comentario = str(comentario).strip()
        if len(texto_comentario) < 5:
            # Comentarios muy cortos suelen ser ruido (plantillas viejas de IE).
            continue
        for patron, etiqueta in patrones_sospechosos:
            if re.search(patron, texto_comentario, re.IGNORECASE):
                resumen = texto_comentario[:120].replace("\n", " ")
                hallazgo_print("MEDIO",
                               f"Comentario HTML con {etiqueta}: {resumen[:80]}...")
                hallazgos.append({
                    "categoria": "HTML",
                    "tipo": "Comentario HTML potencialmente sensible",
                    "elemento": "<!-- ... -->",
                    "valor_observado": resumen,
                    "severidad": "MEDIO",
                    "owasp": "API8:2023 - Security Misconfiguration",
                    "descripcion": f"Comentario contiene patrón sospechoso: {etiqueta}",
                    "vector_ataque": "Filtración de información en código fuente",
                    "escenario": f"El atacante revisa el HTML con Ctrl+U y encuentra el comentario que menciona '{etiqueta}'. Esto le revela TODOs internos, rutas no documentadas, posibles credenciales o IPs internas que el equipo de desarrollo dejó olvidadas.",
                    "impacto": "Pistas para reconocimiento; en el peor caso, exposición directa de credenciales o rutas privadas.",
                    "recomendacion": "Eliminar comentarios técnicos del HTML servido en producción",
                    "referencia": "OWASP Testing Guide - Review Webpage Content for Information Leakage",
                })
                break

    # Formularios
    formularios = soup.find_all("form")
    if formularios:
        hallazgo_print("INFO", f"Se encontraron {len(formularios)} formularios")

    for i, form in enumerate(formularios, 1):
        action = form.get("action", "")

        if action.startswith("http://"):
            hallazgo_print("ALTO",
                           f"Formulario #{i} envía datos a una URL HTTP: {action}")
            hallazgos.append({
                "categoria": "Formularios",
                "tipo": "Formulario sin cifrado",
                "elemento": f"<form action='{action}'>",
                "valor_observado": action,
                "severidad": "ALTO",
                "owasp": "API2:2023 - Broken Authentication",
                "descripcion": "El formulario envía datos en texto plano",
                "vector_ataque": "Captura de credenciales por sniffing",
                "escenario": "Aunque la página de login se sirve por HTTPS, al enviar el formulario los datos viajan por HTTP sin cifrar. Cualquier atacante en la ruta de red (WiFi pública, ISP comprometido, proxy corporativo) captura credenciales en texto plano.",
                "impacto": "Robo directo de credenciales (usuario y contraseña). El atacante toma control de la cuenta sin necesidad de explotar más vulnerabilidades.",
                "recomendacion": "Cambiar el action a HTTPS",
                "referencia": "OWASP ASVS V9.1",
            })

        for input_tag in form.find_all("input", {"type": "password"}):
            autocomplete = input_tag.get("autocomplete", "").lower()
            if autocomplete != "off" and autocomplete != "new-password":
                hallazgo_print("BAJO", f"Input password #{i} permite autocompletar")
                hallazgos.append({
                    "categoria": "Formularios",
                    "tipo": "Input password sin autocomplete=off",
                    "elemento": "<input type='password'>",
                    "valor_observado": f"autocomplete='{autocomplete or 'no especificado'}'",
                    "severidad": "BAJO",
                    "owasp": "API2:2023 - Broken Authentication",
                    "descripcion": "El navegador puede guardar y autocompletar la contraseña",
                    "vector_ataque": "Acceso a credenciales almacenadas en navegador",
                    "escenario": "Si el navegador guarda la contraseña y otra persona accede al equipo (compartido, cibercafé, robo), puede iniciar sesión con autocompletado o extraer las credenciales del gestor del navegador con herramientas como LaZagne.",
                    "impacto": "Acceso no autorizado a la cuenta del usuario en escenarios de equipo compartido o robo de dispositivo.",
                    "recomendacion": "Para campos sensibles usar autocomplete='off' o 'new-password'",
                    "referencia": "OWASP ASVS V8.2",
                })
                break

    # Mixed content: recursos HTTP en página HTTPS.
    if url.startswith("https://"):
        recursos_inseguros = []
        for tag, attr in [("script", "src"), ("link", "href"), ("img", "src"),
                          ("iframe", "src"), ("video", "src"), ("audio", "src")]:
            for elemento in soup.find_all(tag):
                recurso = elemento.get(attr, "")
                if recurso.startswith("http://"):
                    recursos_inseguros.append(f"<{tag} {attr}='{recurso}'>")

        if recursos_inseguros:
            hallazgo_print("ALTO",
                           f"Mixed content: {len(recursos_inseguros)} recursos HTTP en página HTTPS")
            for recurso in recursos_inseguros[:5]:
                print(f"           - {recurso[:100]}")
            hallazgos.append({
                "categoria": "HTML",
                "tipo": "Mixed content (recursos HTTP en página HTTPS)",
                "elemento": "Múltiples elementos",
                "valor_observado": f"{len(recursos_inseguros)} recurso(s) cargado(s) por HTTP",
                "severidad": "ALTO",
                "owasp": "API8:2023 - Security Misconfiguration",
                "descripcion": "La página HTTPS incluye recursos cargados sin cifrado",
                "vector_ataque": "Inyección de código vía recursos HTTP no cifrados",
                "escenario": "Aunque la página principal se sirve por HTTPS, scripts o estilos externos vienen por HTTP. Un atacante MITM modifica esos recursos en tránsito e inyecta JavaScript malicioso, que el navegador ejecuta dentro del contexto del sitio HTTPS.",
                "impacto": "Bypass total del cifrado de la página; el atacante ejecuta código en el contexto autenticado del sitio.",
                "recomendacion": "Cambiar todas las URLs http:// a https:// o usar URLs relativas a protocolo",
                "referencia": "W3C Mixed Content",
            })
        else:
            hallazgo_print("OK", "No se detectó mixed content")

    return hallazgos


# Módulo 6 - Endpoints API
# ------------------------

def detectar_endpoints_api(url, response):
    """Busca referencias a endpoints de API en el HTML y JS público.

    Las SPAs modernas suelen exponer todas sus rutas de API en el bundle JS
    porque el cliente necesita conocerlas. Eso significa que un atacante
    también las conoce con solo leer el código fuente.
    """
    hallazgos = []
    seccion("Detección de endpoints API expuestos")

    patrones = [
        (r"/api/v\d+/[\w/\-]+", "endpoint /api/vN/..."),
        (r"/rest/[\w/\-]+", "endpoint /rest/..."),
        (r"/graphql\b", "endpoint GraphQL"),
        (r"swagger[\-_]?ui", "Swagger UI"),
        (r"/swagger\.json", "definición OpenAPI"),
        (r"/openapi\.json", "definición OpenAPI"),
        (r"/api[\-_]docs", "documentación de API"),
        (r"/v\d+/auth\b", "endpoint de autenticación"),
        (r"/oauth/?(token|authorize)", "endpoint OAuth"),
    ]

    encontrados = set()
    texto = response.text

    for patron, descripcion in patrones:
        matches = re.findall(patron, texto, re.IGNORECASE)
        for match in matches:
            encontrados.add((match, descripcion))

    if not encontrados:
        hallazgo_print("OK",
                       "No se detectaron endpoints API en el código fuente público")
        return hallazgos

    for endpoint, descripcion in sorted(encontrados):
        hallazgo_print("INFO", f"{descripcion}: {endpoint}")
        hallazgos.append({
            "categoria": "Endpoints API",
            "tipo": "Endpoint API referenciado en código público",
            "elemento": descripcion,
            "valor_observado": endpoint,
            "severidad": "BAJO",
            "owasp": "API9:2023 - Improper Inventory Management",
            "descripcion": "Endpoint de API visible en el HTML/JS público",
            "vector_ataque": "Mapeo de superficie de ataque de la API",
            "escenario": f"El atacante extrae '{endpoint}' del código JavaScript público y lo usa como punto de partida para enumerar parámetros, métodos HTTP soportados y comportamientos. Endpoints como /swagger o /openapi.json pueden dar el inventario completo de la API sin esfuerzo.",
            "impacto": "Reduce el reconocimiento de horas a segundos; permite al atacante conocer todos los endpoints sin probar a ciegas.",
            "recomendacion": "Documentar formalmente el endpoint y aplicar autenticación adecuada",
            "referencia": "OWASP API Security Top 10:2023",
        })

    return hallazgos


# Módulo 7 - Archivos de metadatos estandarizados
# -----------------------------------------------

def revisar_archivos_estandar(base_url):
    """Pide los archivos públicos normalizados por estándares web.

    Estos archivos están específicamente pensados para ser leídos por
    cualquiera. No es exploración: es lectura de documentación pública.

      - robots.txt (estándar de facto desde 1994)
      - sitemap.xml (Sitemaps Protocol)
      - .well-known/security.txt (RFC 9116)
      - humans.txt (humanstxt.org)

    Aún así hay info útil: robots.txt a veces lista directorios privados
    "para que Google no los indexe", lo cual es paradójico porque le dice
    al atacante exactamente dónde buscar.
    """
    hallazgos = []
    seccion("Revisión de archivos de metadatos estandarizados")

    parsed = urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    archivos = [
        ("/robots.txt",                "Estándar robots.txt"),
        ("/sitemap.xml",               "Sitemap XML"),
        ("/.well-known/security.txt",  "RFC 9116 - security.txt"),
        ("/humans.txt",                "humans.txt"),
    ]

    for ruta, descripcion in archivos:
        url_completa = base + ruta
        try:
            r = requests.get(url_completa, headers=HEADERS_DEFAULT,
                             timeout=TIMEOUT, verify=False, allow_redirects=False)
            if r.status_code == 200 and len(r.text) > 0:
                hallazgo_print("INFO", f"Encontrado: {ruta} ({len(r.text)} bytes)")

                if ruta == "/robots.txt":
                    rutas_sensibles = re.findall(
                        r"Disallow:\s*(/(?:admin|backup|private|secret|internal|api|test|dev|staging)[^\s]*)",
                        r.text, re.IGNORECASE
                    )
                    if rutas_sensibles:
                        hallazgo_print("MEDIO",
                                       f"robots.txt lista {len(rutas_sensibles)} rutas potencialmente sensibles")
                        for ruta_sens in rutas_sensibles[:5]:
                            print(f"           - {ruta_sens}")
                        hallazgos.append({
                            "categoria": "Archivos públicos",
                            "tipo": "robots.txt expone rutas sensibles",
                            "elemento": "/robots.txt",
                            "valor_observado": ", ".join(rutas_sensibles[:5]),
                            "severidad": "MEDIO",
                            "owasp": "API8:2023 - Security Misconfiguration",
                            "descripcion": "robots.txt enumera rutas que el administrador quiere ocultar (lo cual las expone)",
                            "vector_ataque": "Reconocimiento dirigido a partir de robots.txt",
                            "escenario": "El atacante lee /robots.txt y obtiene una lista directa de rutas que el administrador quiere ocultar de buscadores. Paradójicamente, esas son las rutas más interesantes para atacar: /admin, /backup, /private, etc.",
                            "impacto": "Mapa directo de rutas potencialmente sensibles; el atacante salta la fase de descubrimiento y va directo a probar las rutas listadas.",
                            "recomendacion": "Proteger las rutas con autenticación en lugar de listarlas en robots.txt",
                            "referencia": "OWASP Testing Guide - Review robots.txt",
                        })

                if ruta == "/.well-known/security.txt":
                    hallazgo_print("OK",
                                   "El sitio publica security.txt (canal de divulgación de vulnerabilidades)")
            elif r.status_code == 404:
                if ruta == "/.well-known/security.txt":
                    hallazgo_print("BAJO",
                                   "No publica security.txt (RFC 9116) - canal recomendado para reportar vulnerabilidades")
                    hallazgos.append({
                        "categoria": "Archivos públicos",
                        "tipo": "Falta canal de divulgación de vulnerabilidades",
                        "elemento": "/.well-known/security.txt",
                        "valor_observado": "no encontrado",
                        "severidad": "BAJO",
                        "owasp": "API10:2023 - Unsafe Consumption of APIs",
                        "descripcion": "El sitio no publica un archivo security.txt según RFC 9116",
                        "vector_ataque": "Obstáculo para divulgación responsable",
                        "escenario": "Un investigador de seguridad encuentra una vulnerabilidad pero no sabe a quién reportarla. Sin canal formal, las opciones son: contactar a un email genérico (que puede ignorarse), publicar la vulnerabilidad sin coordinar (full disclosure), o venderla en mercados grises.",
                        "impacto": "Las vulnerabilidades reales pueden quedar sin reportar, sin parchear o publicarse antes de la corrección.",
                        "recomendacion": "Publicar /.well-known/security.txt con email de contacto y política",
                        "referencia": "RFC 9116",
                    })
        except requests.RequestException:
            # Que un archivo no exista es información, no error. Silencio aquí.
            pass

    return hallazgos


# Módulo 8 - Redirecciones
# ------------------------

def analizar_redirecciones(url):
    """Sigue las redirecciones desde la URL inicial y reporta la cadena.

    Cadenas largas son sospechosas: pueden indicar configuración descuidada,
    balanceadores mal puestos, o (peor) que el sitio fue vendido y ahora
    redirige a otro dominio. También verifico que cualquier redirección
    desde HTTP vaya directo a HTTPS.
    """
    hallazgos = []
    seccion("Análisis de cadena de redirecciones")

    try:
        r = requests.get(url, headers=HEADERS_DEFAULT, timeout=TIMEOUT,
                         verify=False, allow_redirects=True)

        if not r.history:
            hallazgo_print("INFO", "Sin redirecciones (respuesta directa)")
            return hallazgos

        hallazgo_print("INFO", f"Cadena de {len(r.history)} redirección(es)")
        for i, paso in enumerate(r.history, 1):
            print(f"           {i}. [{paso.status_code}] {paso.url}")
        print(f"           {len(r.history)+1}. [{r.status_code}] {r.url} (final)")

        # Cadenas de más de 3 redirecciones suelen ser síntoma de algo raro.
        if len(r.history) > 3:
            hallazgo_print("BAJO",
                           f"Cadena de redirecciones larga ({len(r.history)} saltos)")
            hallazgos.append({
                "categoria": "Redirecciones",
                "tipo": "Cadena de redirecciones excesiva",
                "elemento": "Redirect chain",
                "valor_observado": f"{len(r.history)} saltos",
                "severidad": "BAJO",
                "owasp": "API8:2023 - Security Misconfiguration",
                "descripcion": "Múltiples redirecciones aumentan la superficie de ataque y latencia",
                "vector_ataque": "Open Redirect o configuración descuidada",
                "escenario": "Cadenas largas de redirección suelen indicar configuración descuidada (mod_rewrite con reglas redundantes, balanceadores mal configurados). En el peor caso, alguno de los pasos intermedios puede ser un Open Redirect explotable.",
                "impacto": "Latencia adicional, mayor superficie de ataque, posible vulnerabilidad de Open Redirect en saltos intermedios.",
                "recomendacion": "Reducir la cadena a una sola redirección directa",
                "referencia": "OWASP Testing Guide - Test for Open Redirect",
            })

        for paso in r.history:
            if paso.url.startswith("http://"):
                hallazgo_print("MEDIO",
                               f"Redirección pasa por HTTP plano: {paso.url}")
                hallazgos.append({
                    "categoria": "Redirecciones",
                    "tipo": "Redirección por HTTP plano",
                    "elemento": "Redirect chain",
                    "valor_observado": paso.url,
                    "severidad": "MEDIO",
                    "owasp": "API8:2023 - Security Misconfiguration",
                    "descripcion": "Parte de la cadena de redirecciones viaja sin cifrado",
                    "vector_ataque": "Hijacking de redirección por MITM",
                    "escenario": "Aunque el destino final es HTTPS, hay un paso intermedio HTTP. Un atacante MITM puede secuestrar ese salto y redirigir al usuario a un sitio falso (clon del original) en lugar del destino legítimo.",
                    "impacto": "Phishing dirigido invisible para el usuario; el atacante captura credenciales en el sitio falso.",
                    "recomendacion": "Configurar redirección 301 directa de HTTP a HTTPS final",
                    "referencia": "Mozilla Server Side TLS Guidelines",
                })

    except requests.RequestException as e:
        hallazgo_print("INFO", f"No se pudo seguir redirecciones: {e}")

    return hallazgos


# Orquestador
# -----------

def auditar(target):
    """Ejecuta todos los módulos sobre un target y devuelve los hallazgos consolidados."""
    nombre = target["nombre"]
    url = target["url"]
    banner(f"Auditando: {nombre}")
    print(f"  URL: {url}")
    print(f"  Hora: {datetime.now().isoformat()}")

    resumen = {
        "sistema": nombre,
        "url": url,
        "timestamp": datetime.now().isoformat(),
        "estado_http": None,
        "tamano_respuesta_bytes": None,
        "hallazgos": [],
        "error": None,
    }

    try:
        response = requests.get(url, headers=HEADERS_DEFAULT, timeout=TIMEOUT,
                                verify=False, allow_redirects=True)
        resumen["estado_http"] = response.status_code
        resumen["tamano_respuesta_bytes"] = len(response.content)
        resumen["url_final"] = response.url

        seccion(f"Estado HTTP: {response.status_code}")
        seccion(f"Tamaño de respuesta: {len(response.content):,} bytes")

        # Cada módulo es independiente. Si uno falla, los demás siguen.
        try: resumen["hallazgos"] += analizar_cabeceras_http(url, response)
        except Exception as e: print(f"     [error en cabeceras] {e}")

        try: resumen["hallazgos"] += analizar_cookies(url, response)
        except Exception as e: print(f"     [error en cookies] {e}")

        try: resumen["hallazgos"] += analizar_cors(url, response)
        except Exception as e: print(f"     [error en CORS] {e}")

        try: resumen["hallazgos"] += analizar_tls(url)
        except Exception as e: print(f"     [error en TLS] {e}")

        try: resumen["hallazgos"] += analizar_html(url, response)
        except Exception as e: print(f"     [error en HTML] {e}")

        try: resumen["hallazgos"] += detectar_endpoints_api(url, response)
        except Exception as e: print(f"     [error en endpoints] {e}")

        try: resumen["hallazgos"] += revisar_archivos_estandar(url)
        except Exception as e: print(f"     [error en archivos] {e}")

        try: resumen["hallazgos"] += analizar_redirecciones(url)
        except Exception as e: print(f"     [error en redirecciones] {e}")

    except requests.RequestException as e:
        resumen["error"] = str(e)
        print(f"\n  [!!] No se pudo conectar al target: {e}")

    seccion(f"Total hallazgos: {len(resumen['hallazgos'])}")
    conteo_severidad = {}
    for h in resumen["hallazgos"]:
        sev = h["severidad"]
        conteo_severidad[sev] = conteo_severidad.get(sev, 0) + 1
    for sev in ["CRITICO", "ALTO", "MEDIO", "BAJO"]:
        if sev in conteo_severidad:
            print(f"     {sev}: {conteo_severidad[sev]}")

    return resumen


# Reporte en Excel (lo que va al paper)
# -------------------------------------

def generar_excel(resultados, ruta_salida):
    """Genera el reporte Excel con varias hojas.

    Cada hoja sirve para un propósito distinto del artículo:
      - Resumen ejecutivo: tabla compacta para incluir en el paper.
      - Hallazgos detallados: una fila por hallazgo, con vector, escenario e impacto.
      - Por categoría: agrupación útil para gráficos.
      - Metodología: bloque de metadatos para anexar al artículo.
    """
    filas_hallazgos = []
    for r in resultados:
        for h in r["hallazgos"]:
            filas_hallazgos.append({
                "Sistema": r["sistema"],
                "URL": r["url"],
                "Fecha": r["timestamp"][:19],
                "HTTP": r.get("estado_http"),
                "Categoría": h["categoria"],
                "Tipo de hallazgo": h["tipo"],
                "Elemento": h["elemento"],
                "Valor observado": h["valor_observado"],
                "Severidad": h["severidad"],
                "OWASP API Top 10:2023": h["owasp"],
                "Descripción": h["descripcion"],
                # Las tres columnas que dan análisis directo para el paper.
                "Vector de ataque": h.get("vector_ataque", "N/A"),
                "Escenario concreto": h.get("escenario", "N/A"),
                "Impacto / Consecuencia": h.get("impacto", "N/A"),
                "Recomendación": h["recomendacion"],
                "Referencia": h["referencia"],
            })

    df_hallazgos = pd.DataFrame(filas_hallazgos)

    filas_resumen = []
    for r in resultados:
        conteo = {"CRITICO": 0, "ALTO": 0, "MEDIO": 0, "BAJO": 0}
        for h in r["hallazgos"]:
            sev = h["severidad"]
            if sev in conteo:
                conteo[sev] += 1
        filas_resumen.append({
            "Sistema": r["sistema"],
            "URL": r["url"],
            "HTTP": r.get("estado_http"),
            "Críticos": conteo["CRITICO"],
            "Altos": conteo["ALTO"],
            "Medios": conteo["MEDIO"],
            "Bajos": conteo["BAJO"],
            "Total": len(r["hallazgos"]),
        })
    df_resumen = pd.DataFrame(filas_resumen)

    # Hoja "por categoría": útil para sacar gráficas por tipo de problema.
    if filas_hallazgos:
        df_categorias = (df_hallazgos
                         .groupby(["Sistema", "Categoría"])
                         .size()
                         .reset_index(name="Cantidad"))
    else:
        df_categorias = pd.DataFrame(columns=["Sistema", "Categoría", "Cantidad"])

    df_metodologia = pd.DataFrame([
        {"Aspecto": "Marco de referencia",   "Detalle": "OWASP API Security Top 10:2023"},
        {"Aspecto": "Tipo de análisis",      "Detalle": "Pasivo, no intrusivo"},
        {"Aspecto": "Herramientas",          "Detalle": "Python 3, requests, BeautifulSoup4, ssl"},
        {"Aspecto": "Técnicas aplicadas",    "Detalle": "Inspección de cabeceras HTTP, análisis de cookies, "
                                                       "validación TLS, parseo de HTML público, lectura de "
                                                       "archivos estandarizados (robots.txt, security.txt)"},
        {"Aspecto": "Restricciones éticas",  "Detalle": "Sin pruebas de penetración activa, sin payloads, "
                                                       "sin acceso autenticado, sin enumeración por fuerza bruta"},
        {"Aspecto": "Reproducibilidad",      "Detalle": "Código fuente publicado en repositorio abierto"},
        {"Aspecto": "Fecha de auditoría",    "Detalle": datetime.now().strftime("%Y-%m-%d")},
        {"Aspecto": "Targets analizados",    "Detalle": ", ".join(t["nombre"] for t in TARGETS)},
    ])

    with pd.ExcelWriter(ruta_salida, engine="openpyxl") as writer:
        df_resumen.to_excel(writer, sheet_name="Resumen ejecutivo", index=False)
        df_hallazgos.to_excel(writer, sheet_name="Hallazgos detallados", index=False)
        df_categorias.to_excel(writer, sheet_name="Por categoría", index=False)
        df_metodologia.to_excel(writer, sheet_name="Metodología", index=False)


def generar_json(resultados, ruta_salida):
    """Guarda los datos crudos en JSON, útil para post-procesamiento."""
    with open(ruta_salida, "w", encoding="utf-8") as f:
        json.dump(resultados, f, ensure_ascii=False, indent=2, default=str)


# Punto de entrada
# ----------------

def main():
    banner("AUDITOR PASIVO DE SEGURIDAD WEB")
    print("  Marco: OWASP API Security Top 10:2023")
    print("  Tipo:  Pasivo, no intrusivo")
    print(f"  Inicio: {datetime.now().isoformat()}")

    # Crear carpeta de reportes si no existe (para que el repo no necesite
    # tener una carpeta vacía con .gitkeep).
    os.makedirs(CARPETA_REPORTES, exist_ok=True)

    resultados = []
    for target in TARGETS:
        resultado = auditar(target)
        resultados.append(resultado)

    banner("GENERANDO REPORTES")

    ruta_excel = os.path.join(CARPETA_REPORTES, "reporte_seguridad.xlsx")
    ruta_json = os.path.join(CARPETA_REPORTES, "resultados.json")

    generar_excel(resultados, ruta_excel)
    print(f"  [+] Excel generado:  {ruta_excel}")

    generar_json(resultados, ruta_json)
    print(f"  [+] JSON generado:   {ruta_json}")

    banner("RESUMEN FINAL")
    print(f"  {'Sistema':<45} {'HTTP':>6} {'Hallazgos':>10}")
    print(f"  {'-' * 70}")
    for r in resultados:
        nombre = r["sistema"][:43]
        http = str(r.get("estado_http") or "ERR")[:6]
        total = len(r["hallazgos"])
        print(f"  {nombre:<45} {http:>6} {total:>10}")

    total_general = sum(len(r["hallazgos"]) for r in resultados)
    print(f"\n  Total de hallazgos en toda la auditoría: {total_general}")
    print(f"  Fin: {datetime.now().isoformat()}\n")


if __name__ == "__main__":
    main()
