# Phishing Analyzer

Herramienta modular en Python para el análisis forense estático de correos electrónicos (`.eml`), detección de indicadores de suplantación (*spoofing*) y clasificación automatizada de riesgo.

## Capacidades principales

* **Análisis de cabeceras:** Detecta discrepancias entre `From`, `Return-Path`, `Reply-To` y `Message-ID`.
* **Validación de autenticación:** Evalúa registros `SPF`, `DKIM` y `DMARC` en cabeceras `Authentication-Results`.
* **Auditoría de enlaces:** Identifica conexiones sin cifrado (`http://`), dominios externos al remitente y extensiones de alto riesgo (`.xyz`, `.top`, `.click`, `.tk`, `.zip`).
* **Inspección de adjuntos y hashing:** Calcula huellas criptográficas `SHA-256` y detecta ejecutables peligrosos o técnicas de doble extensión (ej. `.pdf.exe`).
* **Inteligencia de amenazas (VirusTotal API v3):** Consulta reputación de hashes mediante `VT_API_KEY` con respaldo automático sin conexión (*fallback*).
* **Clasificación y exportación:** Asigna nivel de riesgo (`BLANCO`, `NARANJA`, `ROJO`) y exporta reportes estructurados en formato `JSON`.

## Estructura del proyecto

```text
phishing-analyzer/
├── src/
│   ├── eml_parser.py      # Extracción de cabeceras, autenticación, URLs y adjuntos
│   ├── analyzer.py        # Motor de reglas, puntuación y clasificación de riesgo
│   ├── threat_intel.py    # Consulta de hashes SHA-256 en VirusTotal API v3
│   └── main.py            # Interfaz de línea de comandos (CLI) y exportación JSON
├── samples/               # Correos .eml de prueba (limpio, sospechoso y malicioso)
├── requirements.txt       # Dependencias del proyecto
└── README.md
