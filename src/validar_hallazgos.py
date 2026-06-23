"""
Validación cruzada automatizada de una submuestra de hallazgos (observación R1-7).

Requiere: pip install requests --break-system-packages   (en Windows, sin el flag)

Uso: python validar_hallazgos.py

Lee resultados.json (el reporte original de la herramienta), toma la misma
muestra estratificada de 25 hallazgos que ya se revisó manualmente, vuelve a
consultar cada portal en vivo y guarda un JSON con el resultado de cada
verificación, listo para anexar como material suplementario.
"""

import json
import os
import random
import re
import sys
import time
from collections import defaultdict

import requests

# Configuración

# El script vive en .../src/. El reporte vive en .../reports/, una carpeta
# arriba y al lado de src/. Esto se calcula a partir de la ubicación real del
# archivo .py, no de la carpeta desde donde lo ejecutes.
CARPETA_SCRIPT = os.path.dirname(os.path.abspath(__file__))
CARPETA_PROYECTO = os.path.dirname(CARPETA_SCRIPT) # un nivel arriba de src/
CARPETA_REPORTS = os.path.join(CARPETA_PROYECTO, "reports")
NOMBRE_JSON_POR_DEFECTO = "resultados.json"

SALIDA_JSON = os.path.join(CARPETA_REPORTS, "validacion_R17.json")
TIMEOUT = 15
PAUSA_ENTRE_PORTALES = (1.0, 3.0) # segundos, pausa aleatoria entre URLs distintas

UA = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
    )
}

URL = {
    "SRI - Servicios en Línea": "https://srienlinea.sri.gob.ec/",
    "Registro Civil en Línea": "https://apps.registrocivil.gob.ec/",
    "SERCOP - Sistema Oficial de Contratación Pública": "https://www.compraspublicas.gob.ec/",
    "IESS - Afiliados": "https://app.iess.gob.ec/",
    "Ministerio de Educación": "https://educacion.gob.ec/",
    "SENESCYT - Consulta de Títulos": "https://www.senescyt.gob.ec/",
    "ANT - Consulta de Licencias y Citaciones": "https://consultaweb.ant.gob.ec/PortalWEB/",
    "ANT - Sistema Virtual de Turnos": "https://consultaweb.ant.gob.ec/SVT/",
    "CNE - Consulta de Lugar de Votación": "https://lugarvotacion.cne.gob.ec/",
}

CUOTA = {"API8": 13, "API2": 6, "API3": 3, "API10": 2, "API9": 1}

ORIGEN_PRUEBA_CORS = "https://sitio-ajeno.example.com"


# Muestreo (idéntico al usado en la revisión manual previa)

def localizar_json(ruta_forzada=None):
    """
    Decide qué archivo .json usar, en este orden:
    1. Si se pasó una ruta por argumento de línea de comandos, se usa esa.
    2. Si existe reports/resultados.json (junto a src/), se usa esa.
    3. Si reports/ existe pero el nombre es distinto, busca cualquier .json
       ahí y lo usa si hay exactamente uno; si hay varios, pide elegir.
    4. Si nada de eso aparece, explica dónde buscó y qué encontró.
    """
    if ruta_forzada:
        if os.path.isfile(ruta_forzada):
            return ruta_forzada
        print(f"\nLa ruta indicada no existe: {os.path.abspath(ruta_forzada)}")
        sys.exit(1)

    ruta_por_defecto = os.path.join(CARPETA_REPORTS, NOMBRE_JSON_POR_DEFECTO)
    if os.path.isfile(ruta_por_defecto):
        return ruta_por_defecto

    if os.path.isdir(CARPETA_REPORTS):
        candidatos = [f for f in os.listdir(CARPETA_REPORTS) if f.lower().endswith(".json")]
        if len(candidatos) == 1:
            print(f"Usando {candidatos[0]} (encontrado en reports/, nombre distinto al esperado).")
            return os.path.join(CARPETA_REPORTS, candidatos[0])
        if len(candidatos) > 1:
            print(f"\nHay varios .json en {CARPETA_REPORTS} y no sé cuál usar:")
            for c in candidatos:
                print(f"  - {c}")
            print('\nEjecuta de nuevo así: python validar_hallazgos.py "ruta\\al\\archivo.json"')
            sys.exit(1)

    print(f"\nNo se encontró ningún .json en: {CARPETA_REPORTS}")
    print(f"(se calculó como ../reports/ a partir de la ubicación de este script: {CARPETA_SCRIPT})")
    if not os.path.isdir(CARPETA_REPORTS):
        print("Esa carpeta 'reports' ni siquiera existe en esa ubicación.")
    print(
        '\nSugerencia: busca la ruta real con PowerShell y ejecuta así:\n'
        '  Get-ChildItem -Recurse -Filter *.json\n'
        '  python validar_hallazgos.py "C:\\ruta\\completa\\resultados.json"\n'
    )
    sys.exit(1)


def cargar_muestra(ruta_json, cuota):
    """Reconstruye la misma muestra estratificada de 25 hallazgos (seed=42)."""
    random.seed(42)
    datos = json.load(open(ruta_json, encoding="utf-8"))

    por_categoria = defaultdict(list)
    for sistema in datos:
        for hallazgo in sistema["hallazgos"]:
            categoria = hallazgo["owasp"].split(":")[0]
            entrada = dict(hallazgo)
            entrada["sistema"] = sistema["sistema"]
            por_categoria[categoria].append(entrada)

    muestra = []
    for categoria, n in cuota.items():
        disponibles = por_categoria[categoria]
        muestra.extend(random.sample(disponibles, min(n, len(disponibles))))
    return muestra


# Utilidades de red

def obtener(url, origen=None):
    """GET simple, no intrusivo. Devuelve headers, cuerpo y cookies crudas."""
    headers = dict(UA)
    if origen:
        headers["Origin"] = origen
    try:
        r = requests.get(url, headers=headers, timeout=TIMEOUT, allow_redirects=True)
        set_cookie = []
        if hasattr(r.raw, "headers") and hasattr(r.raw.headers, "get_all"):
            set_cookie = r.raw.headers.get_all("Set-Cookie") or []
        elif "Set-Cookie" in r.headers:
            set_cookie = [r.headers["Set-Cookie"]]
        return {
            "ok": True,
            "status": r.status_code,
            "headers": dict(r.headers),
            "texto": r.text,
            "set_cookie": set_cookie,
        }
    except requests.RequestException as e:
        return {"ok": False, "error": str(e)}


# Verificación por categoría

def verificar(hallazgo, cache):
    url = URL[hallazgo["sistema"]]
    categoria = hallazgo["categoria"]
    tipo = hallazgo["tipo"]
    elemento = hallazgo["elemento"]

    if url not in cache:
        cache[url] = obtener(url)
        time.sleep(random.uniform(*PAUSA_ENTRE_PORTALES))
    base = cache[url]

    resultado = {"metodo": None, "detalle": None, "coincide": None}

    if not base["ok"]:
        resultado["metodo"] = "GET"
        resultado["detalle"] = f"error de conexión: {base['error']}"
        return resultado

    headers_lower = {k.lower(): v for k, v in base["headers"].items()}

    if categoria == "Cabeceras HTTP":
        resultado["metodo"] = "GET, inspección de cabeceras de respuesta"
        presente = elemento.lower() in headers_lower
        resultado["detalle"] = headers_lower.get(elemento.lower())
        if tipo == "Cabecera de seguridad ausente":
            resultado["coincide"] = not presente
        else:  # Filtración de información: la cabecera SIGUE presente
            resultado["coincide"] = presente

    elif categoria == "Cookies":
        resultado["metodo"] = "GET, inspección de Set-Cookie"
        nombre_cookie = elemento  # el nombre real de la cookie va en 'elemento'
        cookie_objetivo = next(
            (c for c in base["set_cookie"] if nombre_cookie in c), None
        )
        resultado["detalle"] = cookie_objetivo
        if cookie_objetivo is None:
            resultado["detalle"] = "cookie no encontrada en esta consulta"
        elif tipo == "Cookie con flags de seguridad incompletas":
            cookie_min = cookie_objetivo.lower()
            descripcion = (hallazgo.get("valor_observado") or "").lower()
            # 'valor_observado' suele decir cuál flag falta especificamente;
            # si no lo dice, se revisan los tres flags relevantes.
            if "samesite" in descripcion:
                resultado["coincide"] = "samesite" not in cookie_min
            elif "httponly" in descripcion:
                resultado["coincide"] = "httponly" not in cookie_min
            elif "secure" in descripcion:
                resultado["coincide"] = "secure" not in cookie_min
            else:
                resultado["coincide"] = (
                    "secure" not in cookie_min
                    or "httponly" not in cookie_min
                    or "samesite" not in cookie_min
                )
        elif tipo == "Filtración de stack vía nombre de cookie":
            resultado["coincide"] = True

    elif categoria == "CORS":
        resultado["metodo"] = "GET con cabecera Origin de prueba"
        respuesta_cors = obtener(url, origen=ORIGEN_PRUEBA_CORS)
        acao = respuesta_cors.get("headers", {}).get("Access-Control-Allow-Origin")
        resultado["detalle"] = acao
        resultado["coincide"] = acao in ("*", ORIGEN_PRUEBA_CORS)

    elif categoria == "Archivos públicos":
        resultado["metodo"] = "GET /.well-known/security.txt"
        ruta_sec = url.rstrip("/") + "/.well-known/security.txt"
        respuesta_sec = obtener(ruta_sec)
        resultado["detalle"] = respuesta_sec.get("status", respuesta_sec.get("error"))
        resultado["coincide"] = respuesta_sec.get("status") == 404

    elif categoria == "Endpoints API":
        resultado["metodo"] = "GET cuerpo, búsqueda de patrón /rest/*"
        coincidencia = re.search(r"/rest/[a-zA-Z]+", base["texto"])
        resultado["detalle"] = coincidencia.group(0) if coincidencia else None
        resultado["coincide"] = bool(coincidencia)

    elif categoria in ("HTML", "Formularios"):
        resultado["metodo"] = "GET cuerpo, búsqueda de patrón HTML"
        if "generator" in elemento.lower():
            coincidencia = re.search(
                r"<meta[^>]+name=[\"']generator[\"'][^>]*>", base["texto"], re.I
            )
            resultado["detalle"] = coincidencia.group(0) if coincidencia else None
            resultado["coincide"] = bool(coincidencia)
        else:  # autocomplete en password
            coincidencia = re.search(
                r"<input[^>]+type=[\"']password[\"'][^>]*>", base["texto"], re.I
            )
            resultado["detalle"] = coincidencia.group(0) if coincidencia else None
            if coincidencia:
                tiene_autocomplete_off = "autocomplete=\"off\"" in coincidencia.group(0).lower()
                resultado["coincide"] = not tiene_autocomplete_off
            else:
                resultado["coincide"] = None

    return resultado


# Orquestación

def main():
    ruta_forzada = sys.argv[1] if len(sys.argv) > 1 else None
    ruta_json = localizar_json(ruta_forzada)
    print(f"Usando reporte: {ruta_json}\n")
    muestra = cargar_muestra(ruta_json, CUOTA)
    cache = {}
    salida = []

    for i, hallazgo in enumerate(muestra, 1):
        print(f"[{i}/{len(muestra)}] {hallazgo['sistema']} — {hallazgo['tipo']}")
        verificacion = verificar(hallazgo, cache)
        salida.append({
            "indice": i,
            "sistema": hallazgo["sistema"],
            "owasp": hallazgo["owasp"],
            "tipo": hallazgo["tipo"],
            "elemento": hallazgo["elemento"],
            "severidad": hallazgo["severidad"],
            "verificacion": verificacion,
        })

    coincide = sum(1 for r in salida if r["verificacion"]["coincide"] is True)
    no_coincide = sum(1 for r in salida if r["verificacion"]["coincide"] is False)
    indeterminado = sum(1 for r in salida if r["verificacion"]["coincide"] is None)

    resumen = {
        "total_muestra": len(salida),
        "porcentaje_del_total": round(len(salida) / 101 * 100, 1),
        "coincide": coincide,
        "no_coincide": no_coincide,
        "indeterminado": indeterminado,
        "tasa_falsos_positivos_pct": round(no_coincide / len(salida) * 100, 1) if salida else None,
    }

    with open(SALIDA_JSON, "w", encoding="utf-8") as f:
        json.dump({"resumen": resumen, "detalle": salida}, f, ensure_ascii=False, indent=2)

    print("\n--- Resumen ---")
    print(json.dumps(resumen, ensure_ascii=False, indent=2))
    print(f"\nResultado completo guardado en {SALIDA_JSON}")


if __name__ == "__main__":
    main()
