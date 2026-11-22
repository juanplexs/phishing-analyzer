from eml_parser import parse_eml
from urllib.parse import urlparse
from threat_intel import check_hash_vt
def check_headers(headers):
    score = 0
    alertas = []
    from_dom = headers["from_domain"]

    if headers["return_path"]:
        ret_dom = headers["return_path"].split("@")[-1]
        if ret_dom != from_dom:
            score += 25
            alertas.append(f"Return-Path ({ret_dom}) no coincide con From ({from_dom})")

    if headers["reply_to"]:
        rep_dom = headers["reply_to"].split("@")[-1]
        if rep_dom != from_dom:
            score += 20
            alertas.append(f"Reply-To ({rep_dom}) desvia respuestas fuera de {from_dom}")

    if headers["message_id_domain"] and headers["message_id_domain"] != from_dom:
        score += 15
        alertas.append(f"Message-ID ({headers['message_id_domain']}) distinto a {from_dom}")

    return score, alertas

def check_auth(auth):
    score = 0
    alertas = []

    if auth["spf"] == "fail":
        score += 20
        alertas.append("SPF fallo (fail): servidor remitente no autorizado")
    elif auth["spf"] in ("softfail", "none"):
        score += 10
        alertas.append(f"SPF debil o ausente ({auth['spf']})")

    if auth["dkim"] == "fail":
        score += 20
        alertas.append("DKIM fallo (fail): firma digital invalida o alterada")
    elif auth["dkim"] == "none":
        score += 10
        alertas.append("DKIM ausente (none): correo sin firma criptografica")

    if auth["dmarc"] == "fail":
        score += 25
        alertas.append("DMARC fallo (fail): incumple politica del dominio")
    elif auth["dmarc"] == "none":
        score += 10
        alertas.append("DMARC ausente (none): dominio sin proteccion DMARC")

    return score, alertas
    
def check_urls(urls, from_domain):
    score = 0
    alertas = []
    tlds_sospechosos = (".xyz", ".top", ".click", ".tk", ".zip")

    for url in urls:
        partes = urlparse(url)
        esquema = partes.scheme.lower()
        url_dom = partes.netloc.lower()

        if esquema == "http":
            score += 15
            alertas.append(f"Enlace sin cifrado HTTPS: {url}")

        if url_dom and url_dom != from_domain and not url_dom.endswith(f".{from_domain}"):
            score += 20
            alertas.append(f"Enlace apunta a dominio externo ({url_dom}) distinto a {from_domain}")

        if url_dom.endswith(tlds_sospechosos):
            score += 15
            alertas.append(f"Dominio con extension de alto riesgo en enlace: {url_dom}")

    return score, alertas
    
def check_attachments(attachments):
    score = 0
    alertas = []
    ext_peligrosas = (".exe", ".bat", ".cmd", ".scr", ".vbs", ".js", ".ps1", ".msi")

    for adj in attachments:
        nombre = adj["filename"].lower()

        if nombre.endswith(ext_peligrosas):
            score += 50
            alertas.append(f"Adjunto ejecutable o script peligroso: {adj['filename']}")

        if nombre.count(".") >= 2:
            score += 30
            alertas.append(f"Doble extension sospechosa detectada: {adj['filename']}")

    return score, alertas
            
    
def analyze_email(file_path):
    datos = parse_eml(file_path)

    pts_head, al_head = check_headers(datos["headers"])
    pts_auth, al_auth = check_auth(datos["auth"])
    pts_urls, al_urls = check_urls(datos["urls"], datos["headers"]["from_domain"])
    pts_adj, al_adj = check_attachments(datos["attachments"])
    pts_vt = 0
    al_vt = []
    for adj in datos["attachments"]:
        vt = check_hash_vt(adj["sha256"])
        adj["vt_result"] = vt
        if vt["status"] == "found" and vt["malicious"] > 0:
            pts_vt += 50
            al_vt.append(
                f"VirusTotal: {adj['filename']} detectado como malicioso por {vt['malicious']} motores"
            )
    total_score = pts_head + pts_auth + pts_urls + pts_adj + pts_vt
    todas_alertas = al_head + al_auth + al_urls + al_adj + al_vt

    if pts_adj >= 50 or pts_vt >= 50 or total_score >= 170:
        veredicto = "ROJO (Malicioso)"
    elif total_score >= 30:
        veredicto = "NARANJA (Sospechoso)"
    else:
        veredicto = "BLANCO (Limpio)"

    return {
        "file": file_path,
        "verdict": veredicto,
        "score": total_score,
        "alerts": todas_alertas,
        "attachments": datos["attachments"],
    }


if __name__ == "__main__":
    muestras = [
        "samples/01_solo_texto_blanco.eml",
        "samples/02_spoofing_enlaces_naranja.eml",
        "samples/03_adjunto_ejecutable_rojo.eml",
    ]
    for ruta in muestras:
        res = analyze_email(ruta)
        print(f"{res['file']} -> {res['verdict']} | Puntos: {res['score']}")
