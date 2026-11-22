import os
import requests


def check_hash_vt(sha256_hash):
    api_key = os.environ.get("VT_API_KEY")
    if not api_key:
        return {
            "status": "skipped",
            "reason": "VT_API_KEY no configurada en el entorno",
        }

    url = f"https://www.virustotal.com/api/v3/files/{sha256_hash}"
    headers = {"x-apikey": api_key}

    try:
        respuesta = requests.get(url, headers=headers, timeout=10)
    except requests.RequestException as error:
        return {
            "status": "error",
            "reason": f"Error de red al consultar VirusTotal: {error}",
        }

    if respuesta.status_code == 200:
        datos = respuesta.json()
        stats = datos["data"]["attributes"]["last_analysis_stats"]
        return {
            "status": "found",
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
        }
    elif respuesta.status_code == 404:
        return {
            "status": "not_found",
            "reason": "Hash desconocido en la base de VirusTotal",
        }
    else:
        return {
            "status": "error",
            "reason": f"VirusTotal respondio con codigo HTTP {respuesta.status_code}",
        }


if __name__ == "__main__":
    hash_prueba = "4996837b4f0caec7796bec60cb4038fb262315ddadf42ec5dfbfab5bf79fcfa5"
    print(check_hash_vt(hash_prueba))
