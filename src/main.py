import argparse
import json
from analyzer import analyze_email


def print_report(resultado):
    print("=" * 60)
    print("REPORTE DE ANALISIS DE PHISHING")
    print("=" * 60)
    print(f"Archivo   : {resultado['file']}")
    print(f"Veredicto : {resultado['verdict']}")
    print(f"Puntaje   : {resultado['score']} puntos")
    print("-" * 60)
    print("Alertas detectadas:")
    if resultado["alerts"]:
        for alerta in resultado["alerts"]:
            print(f"  [!] {alerta}")
    else:
        print("  [OK] Sin anomalias detectadas.")

    if resultado["attachments"]:
        print("-" * 60)
        print("Adjuntos analizados:")
        for adj in resultado["attachments"]:
            vt_status = adj.get("vt_result", {}).get("status", "N/A")
            print(f"  - {adj['filename']} | SHA-256: {adj['sha256']} | VT: {vt_status}")
    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(description="Analizador forense de correos EML y phishing")
    parser.add_argument("file", help="Ruta al archivo .eml que deseas analizar")
    parser.add_argument("--json", dest="json_out", help="Ruta opcional para exportar el reporte en JSON")
    args = parser.parse_args()

    resultado = analyze_email(args.file)
    print_report(resultado)

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as archivo_json:
            json.dump(resultado, archivo_json, indent=4, ensure_ascii=False)
        print(f"Reporte exportado en JSON: {args.json_out}")


if __name__ == "__main__":
    main()
