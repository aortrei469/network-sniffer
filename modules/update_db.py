#!/usr/bin/env python3
"""
Actualizador de bases de datos offline para el Network Sniffer

Descarga las últimas versiones de:
- GeoLite2 (MaxMind) - Geolocalización de IPs
- ThreatFox IOC IPs - IPs maliciosas conocidas
- Spamhaus DROP/EDROP - Lista de IPs bloqueadas
"""

import os
import sys
import gzip
import shutil
import json
import requests
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.config import (
    DATABASES_DIR,
    GEOLITE_DB_PATH,
    THREATFOX_DB_PATH,
    SPAMHAUS_DB_PATH,
    THREATFOX_URL,
    SPAMHAUS_DROP_URL,
    SPAMHAUS_EDROP_URL,
    FEODO_URL,
    URLHAUS_URL,
)

os.makedirs(DATABASES_DIR, exist_ok=True)


def download_file(url, output_path, description, headers=None):
    print(f"\n[DOWN] Descargando {description}...")
    print(f"       URL: {url}")

    try:
        response = requests.get(url, headers=headers or {}, timeout=60, stream=True)
        response.raise_for_status()

        with open(output_path, "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)

        size = os.path.getsize(output_path)
        print(f"[DOWN] ✓ {description} guardado ({size:,} bytes)")
        return True

    except requests.RequestException as e:
        print(f"[DOWN] ✗ Error descargando {description}: {e}")
        return False


def download_threatfox():
    print("\n[THREATFOX] Descargando lista de IPs maliciosas...")

    all_ips = set()

    # Intentar Feodo Tracker (botnet C&C)
    try:
        print("[THREATFOX] Descargando Feodo Tracker...")
        response = requests.get(FEODO_URL, timeout=60)
        response.raise_for_status()
        data = response.json()

        # Feodo devuelve una lista directamente
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    ip = item.get("ip_address") or item.get("ip")
                    if ip:
                        all_ips.add(ip)
        elif isinstance(data, dict) and "ip_list" in data:
            for item in data["ip_list"]:
                if isinstance(item, dict):
                    ip = item.get("ip_address") or item.get("ip")
                    if ip:
                        all_ips.add(ip)
        print(f"[THREATFOX]   Feodo: {len(all_ips)} IPs")
    except Exception as e:
        print(f"[THREATFOX]   Error Feodo: {e}")

    # Intentar URLhaus ( URLs maliciosas - extraer dominios/IPs)
    try:
        print("[THREATFOX] Descargando URLhaus...")
        urlhaus_csv_url = "https://urlhaus.abuse.ch/downloads/csv/"
        response = requests.get(urlhaus_csv_url, timeout=60)
        response.raise_for_status()

        for line in response.text.split("\n"):
            line = line.strip()
            if line and not line.startswith("#"):
                parts = line.split(",")
                if len(parts) >= 2:
                    url_or_ip = parts[1].strip()
                    if url_or_ip:
                        import re

                        ip_match = re.search(
                            r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", url_or_ip
                        )
                        if ip_match:
                            all_ips.add(ip_match.group(1))
        print(f"[THREATFOX]   URLhaus: procesando...")
    except Exception as e:
        print(f"[THREATFOX]   Error URLhaus: {e}")

    # Si tenemos IPs, guardar
    if all_ips:
        with open(THREATFOX_DB_PATH, "w") as f:
            for ip in sorted(all_ips):
                f.write(f"{ip}\n")
        print(f"[THREATFOX] ✓ {len(all_ips)} IPs guardadas en {THREATFOX_DB_PATH}")
        return True

    print("[THREATFOX] ✗ No se pudieron descargar listas de amenazas")
    with open(THREATFOX_DB_PATH, "w") as f:
        f.write("# Lista de IPs maliciosas (vacía)\n")
    return False


def download_spamhaus():
    print("\n[SPAMHAUS] Descargando listas de bloqueo...")

    success = True

    if download_file(SPAMHAUS_DROP_URL, SPAMHAUS_DB_PATH, "Spamhaus DROP"):
        pass
    else:
        success = False

    edrop_path = SPAMHAUS_DB_PATH.replace(".txt", "_edrop.txt")
    if download_file(SPAMHAUS_EDROP_URL, edrop_path, "Spamhaus EDROP"):
        with open(SPAMHAUS_DB_PATH, "a") as dst:
            with open(edrop_path, "r") as src:
                for line in src:
                    if line.strip() and not line.startswith(";"):
                        dst.write(line)
        os.remove(edrop_path)

    return success


def download_geolite2():
    print("\n[GEOLITE2] Buscando base de datos GeoIP...")

    possible_paths = [
        "/usr/share/GeoIP/GeoLite2-Country.mmdb",
        "/usr/share/GeoIP/GeoLiteCountry.dat",
        "/var/lib/GeoIP/GeoLite2-Country.mmdb",
    ]

    for alt_path in possible_paths:
        if os.path.exists(alt_path):
            print(f"[GEOLITE2] Encontrada en {alt_path}, copiando...")
            shutil.copy(alt_path, GEOLITE_DB_PATH)
            print(f"[GEOLITE2] ✓ Base de datos copiada")
            return True

    print("[GEOLITE2] No se encontró base de datos del sistema.")
    print("-" * 60)
    print("Intentando descargar base de datos gratuita...")

    # Intentar descargar DB gratuita de ip-api.com (formato JSON más fácil)
    # Nota: Este es un servicio gratuito con límites
    print("[GEOLITE2] Sin base de datos GeoIP offline.")
    print("-" * 60)
    print("Puedes obtener una base de datos gratuitamente:")
    print("  1. db-ip.com - Registro gratuito necesario")
    print("     https://db-ip.com/dbip/download.php")
    print("  2. MaxMind - Requiere cuenta gratuita")
    print("     https://www.maxmind.com/en/geoip2-databases")
    print(f"\nGuarda el archivo como: {GEOLITE_DB_PATH}")
    print("\nEl análisis GeoIP funcionará pero sin información de país/ASN.")

    return False


def update_databases():
    print("=" * 60)
    print("  ACTUALIZADOR DE BASES DE DATOS")
    print("  Network Sniffer v1.0")
    print("=" * 60)
    print(f"Directorio: {DATABASES_DIR}")
    print(f"Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    results = {
        "threatfox": download_threatfox(),
        "spamhaus": download_spamhaus(),
        "geolite2": download_geolite2(),
    }

    print("\n" + "=" * 60)
    print("RESULTADO DE LA ACTUALIZACIÓN")
    print("=" * 60)

    for db, success in results.items():
        status = "✓" if success else "✗"
        print(f"  [{status}] {db}")

    print("=" * 60)

    if os.path.exists(THREATFOX_DB_PATH):
        count = sum(1 for line in open(THREATFOX_DB_PATH) if line.strip())
        print(f"  IPs maliciosas: {count}")

    if os.path.exists(SPAMHAUS_DB_PATH):
        count = sum(
            1
            for line in open(SPAMHAUS_DB_PATH)
            if line.strip() and not line.startswith(";")
        )
        print(f"  IPs bloqueadas (Spamhaus): {count}")

    if os.path.exists(GEOLITE_DB_PATH):
        size = os.path.getsize(GEOLITE_DB_PATH)
        print(f"  GeoIP: {size:,} bytes")

    print("\n[INFO] Para ejecutar el sniffer:")
    print("  cd network_sniffer")
    print("  pip install -r requirements.txt")
    print("  sudo python3 sniffer.py --capture")
    print()
    print("[INFO] Para analizar logs existentes:")
    print("  sudo python3 sniffer.py --analyze -i logs/")


if __name__ == "__main__":
    update_databases()
