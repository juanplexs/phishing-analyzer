import email
from email import policy
from email.utils import parseaddr
import re
import hashlib
def load_email(file_path):
	with open(file_path, "rb") as archivo:
		return email.message_from_binary_file(archivo, policy=policy.default)
		
def extract_headers(msg):
	nombre, direccion = parseaddr(msg["From"])
	dominio = direccion.split("@")[-1]
	retorno = parseaddr(msg.get("Return-Path") or "")[1]
	respuesta = parseaddr(msg.get("Reply-To") or "")[1]
	msg_id = (msg.get("Message-ID") or "").strip("<>")
	msg_id_dominio = msg_id.split("@")[-1]
	return {"from_display": nombre,
	 "from_address": direccion,
	  "from_domain": dominio,
	  "return_path": retorno,
	  "reply_to": respuesta,
	  "subject": msg.get("Subject", ""),
	  "date": msg.get("Date", ""),
	  "message_id_domain": msg_id_dominio,}				

def extract_auth(msg):
    auth_header = (msg.get("Authentication-Results") or "").lower()
    spf = re.search(r"spf=(\w+)", auth_header)
    dkim = re.search(r"dkim=(\w+)", auth_header)
    dmarc = re.search(r"dmarc=(\w+)", auth_header)
    return {
        "spf": spf.group(1) if spf else "none",
        "dkim": dkim.group(1) if dkim else "none",
        "dmarc": dmarc.group(1) if dmarc else "none",
    }
def extract_urls(msg):
    urls = []
    for part in msg.walk():
        if part.get_content_type() in ("text/plain","text/html"):
            cuerpo = part.get_content()
            encontrados = re.findall(r"https?://[^\s\"'<>]+", cuerpo)
            urls.extend(encontrados)
    return list(set(urls))
def extract_attachments(msg):
    adjuntos = []
    for part in msg.walk():
        nombre_archivo = part.get_filename()
        if nombre_archivo:
            contenido = part.get_payload(decode=True) or b""
            sha256 = hashlib.sha256(contenido).hexdigest()
            adjuntos.append({
                "filename": nombre_archivo,
                "content_type": part.get_content_type(),
                "sha256": sha256,
            })
    return adjuntos		
def parse_eml(file_path):
    msg = load_email(file_path)
    return {
        "headers": extract_headers(msg),
        "auth": extract_auth(msg),
        "urls": extract_urls(msg),
        "attachments": extract_attachments(msg),
    }


if __name__ == "__main__":
    resultado = parse_eml("samples/03_adjunto_ejecutable_rojo.eml")
    print(resultado)
