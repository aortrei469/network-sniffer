#!/usr/bin/env python3
"""
Módulo de enriquecimiento de IPs para análisis offline
Incluye:
- Resolución DNS inversa (PTR)
- Consultas WHOIS
- Listas adicionales (Tor, Emerging Threats, DShield)
"""

import os
import re
import socket
import subprocess
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# URLs de listas de amenazas adicionales
TOR_EXIT_NODES_URL = "https://check.torproject.org/torbulkexitlist?ip=1"
EMERGING_THREATS_URL = (
    "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
)
DSHIELD_URL = "https://www.dshield.org/ips.txt"

# Rutas de bases de datos
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATABASES_DIR = os.path.join(BASE_DIR, "databases")

TOR_DB_PATH = os.path.join(DATABASES_DIR, "tor_exit_nodes.txt")
EMERGING_DB_PATH = os.path.join(DATABASES_DIR, "emerging_threats.txt")
DSHIELD_DB_PATH = os.path.join(DATABASES_DIR, "dshield_ips.txt")

WHOIS_CACHE_FILE = os.path.join(DATABASES_DIR, "whois_cache.json")

os.makedirs(DATABASES_DIR, exist_ok=True)


def load_whois_cache():
    """Carga la caché de WHOIS desde archivo"""
    if os.path.exists(WHOIS_CACHE_FILE):
        try:
            import json

            with open(WHOIS_CACHE_FILE, "r") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def save_whois_cache(cache):
    """Guarda la caché de WHOIS a archivo"""
    try:
        import json

        with open(WHOIS_CACHE_FILE, "w") as f:
            json.dump(cache, f, indent=2)
    except Exception:
        pass


def download_additional_lists():
    """Descarga listas adicionales de amenazas"""
    import requests

    results = {}

    # Tor Exit Nodes
    try:
        print("[TOR] Descargando lista de nodos de salida Tor...")
        response = requests.get(TOR_EXIT_NODES_URL, timeout=30)
        response.raise_for_status()

        with open(TOR_DB_PATH, "w") as f:
            f.write(response.text)

        count = len([l for l in response.text.split("\n") if l.strip()])
        print(f"[TOR] ✓ {count} nodos de salida")
        results["tor"] = True
    except Exception as e:
        print(f"[TOR] ✗ Error: {e}")
        results["tor"] = False

    # Emerging Threats
    try:
        print("[EMERGING] Descargando lista de IPs comprometidas...")
        response = requests.get(EMERGING_THREATS_URL, timeout=30)
        response.raise_for_status()

        with open(EMERGING_DB_PATH, "w") as f:
            f.write(response.text)

        count = len(
            [
                l
                for l in response.text.split("\n")
                if l.strip() and not l.startswith("#")
            ]
        )
        print(f"[EMERGING] ✓ {count} IPs comprometidas")
        results["emerging"] = True
    except Exception as e:
        print(f"[EMERGING] ✗ Error: {e}")
        results["emerging"] = False

    # DShield
    try:
        print("[DSHIELD] Descargando lista de DShield...")
        response = requests.get(DSHIELD_URL, timeout=30)
        response.raise_for_status()

        ips = []
        for line in response.text.split("\n"):
            line = line.strip()
            if line and not line.startswith("#"):
                parts = line.split("\t")
                if parts and re.match(r"\d+\.\d+\.\d+\.\d+", parts[0]):
                    ips.append(parts[0])

        with open(DSHIELD_DB_PATH, "w") as f:
            for ip in ips:
                f.write(f"{ip}\n")

        print(f"[DSHIELD] ✓ {len(ips)} IPs reportadas")
        results["dshield"] = True
    except Exception as e:
        print(f"[DSHIELD] ✗ Error: {e}")
        results["dshield"] = False

    return results


def load_additional_lists():
    """Carga las listas adicionales en memoria"""
    lists = {"tor": set(), "emerging": set(), "dshield": set()}

    # Cargar Tor Exit Nodes
    if os.path.exists(TOR_DB_PATH):
        try:
            with open(TOR_DB_PATH, "r") as f:
                for line in f:
                    line = line.strip()
                    if line and re.match(r"\d+\.\d+\.\d+\.\d+", line):
                        lists["tor"].add(line)
            print(f"[ENRICH] Cargados {len(lists['tor'])} nodos Tor")
        except Exception as e:
            print(f"[ENRICH] Error cargando Tor: {e}")

    # Cargar Emerging Threats
    if os.path.exists(EMERGING_DB_PATH):
        try:
            with open(EMERGING_DB_PATH, "r") as f:
                for line in f:
                    line = line.strip()
                    if (
                        line
                        and not line.startswith("#")
                        and re.match(r"\d+\.\d+\.\d+\.\d+", line)
                    ):
                        lists["emerging"].add(line)
            print(f"[ENRICH] Cargadas {len(lists['emerging'])} IPs de Emerging Threats")
        except Exception as e:
            print(f"[ENRICH] Error cargando Emerging: {e}")

    # Cargar DShield
    if os.path.exists(DSHIELD_DB_PATH):
        try:
            with open(DSHIELD_DB_PATH, "r") as f:
                for line in f:
                    line = line.strip()
                    if line and re.match(r"\d+\.\d+\.\d+\.\d+", line):
                        lists["dshield"].add(line)
            print(f"[ENRICH] Cargadas {len(lists['dshield'])} IPs de DShield")
        except Exception as e:
            print(f"[ENRICH] Error cargando DShield: {e}")

    return lists


def resolve_ptr(ip):
    """Resolución DNS inversa (PTR)"""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        return None


def query_whois(ip):
    """Consulta información WHOIS de una IP"""
    try:
        result = subprocess.run(
            ["whois", ip], capture_output=True, text=True, timeout=10
        )

        info = {}
        output = result.stdout

        # Extraer información relevante
        patterns = {
            "netname": r"netname:\s*(.+)",
            "descr": r"descr:\s*(.+)",
            "country": r"country:\s*(.+)",
            "origin": r"origin:\s*(.+)",
            "asn": r"AS(\d+)",
            "org": r"organization:\s*(.+)",
            "abuse": r"abuse-mailbox:\s*(.+)",
            "created": r"created:\s*(.+)",
            "source": r"source:\s*(.+)",
        }

        for key, pattern in patterns.items():
            match = re.search(pattern, output, re.IGNORECASE)
            if match:
                info[key] = match.group(1).strip()

        # Obtener descripción corta
        if "descr" in info:
            info["description"] = info["descr"][:100]
        elif "org" in info:
            info["description"] = info["org"][:100]
        elif "netname" in info:
            info["description"] = info["netname"][:100]

        return info if info else None

    except subprocess.TimeoutExpired:
        return {"error": "timeout"}
    except Exception as e:
        return {"error": str(e)}


def check_ip_list(ip, ip_list):
    """Verifica si una IP está en una lista"""
    return ip in ip_list


def enrich_ip_fast(ip, additional_lists=None):
    """Análisis rápido: solo verifica listas adicionales"""
    result = {
        "ip": ip,
        "ptr": None,
        "whois": None,
        "lists": {"tor": False, "emerging": False, "dshield": False},
        "risk_factors": [],
    }

    if additional_lists:
        # Verificar listas
        if ip in additional_lists.get("tor", set()):
            result["lists"]["tor"] = True
            result["risk_factors"].append("Nodo de salida Tor")

        if ip in additional_lists.get("emerging", set()):
            result["lists"]["emerging"] = True
            result["risk_factors"].append("IP comprometida (Emerging Threats)")

        if ip in additional_lists.get("dshield", set()):
            result["lists"]["dshield"] = True
            result["risk_factors"].append("IP reportada (DShield)")

    return result


def enrich_ip_deep(ip, additional_lists=None, whois_cache=None):
    """Análisis profundo: PTR + WHOIS + listas"""
    result = enrich_ip_fast(ip, additional_lists)

    # Resolución PTR
    ptr = resolve_ptr(ip)
    if ptr:
        result["ptr"] = ptr
        # Si tiene PTR, verificar si es conocido
        ptr_lower = ptr.lower()
        suspicious_keywords = [
            "malware",
            "spam",
            "bot",
            "c2",
            "phishing",
            "scam",
            "hack",
        ]
        if any(kw in ptr_lower for kw in suspicious_keywords):
            result["risk_factors"].append(f"PTR sospechoso: {ptr}")

    # Consulta WHOIS (usar caché si disponible)
    if whois_cache and ip in whois_cache:
        result["whois"] = whois_cache[ip]
    else:
        whois_info = query_whois(ip)
        result["whois"] = whois_info
        if whois_cache and whois_info and "error" not in whois_info:
            whois_cache[ip] = whois_info

    # Analizar información WHOIS
    if result["whois"] and "error" not in result["whois"]:
        whois = result["whois"]

        # Extraer AS y organización
        asn = whois.get("asn") or whois.get("origin", "").replace("AS", "")
        org = whois.get("org") or whois.get("description", "")

        result["asn"] = asn
        result["organization"] = org
        result["country"] = whois.get("country", "")

        # Verificar si es Hosting/Cloud conocido
        hosting_keywords = [
            "amazon",
            "aws",
            "google",
            "microsoft",
            "azure",
            "cloudflare",
            "digitalocean",
            "linode",
            "vultr",
            "ovh",
            "hetzner",
            "alibaba",
            "tencent",
            "akamai",
            "fastly",
            "cloudfront",
        ]
        if org and any(kw in org.lower() for kw in hosting_keywords):
            result["is_hosting"] = True
            result["risk_factors"].append(f"Cloud/Hosting: {org}")

        # Verificar país de riesgo
        high_risk_countries = [
            "KP",
            "IR",
            "SY",
            "CU",
            "VE",
            "BY",
            "RU",
            "CN",
            "KP",
            "IR",
        ]
        if whois.get("country") in high_risk_countries:
            result["risk_factors"].append(f"País de riesgo: {whois.get('country')}")

    return result


def analyze_ips_batch(
    ips, mode="fast", additional_lists=None, whois_cache=None, max_workers=10
):
    """Analiza un lote de IPs"""
    results = {}

    if mode == "fast":
        print(f"[ENRICH] Analizando {len(ips)} IPs en modo RÁPIDO...")
        for ip in ips:
            results[ip] = enrich_ip_fast(ip, additional_lists)
    else:
        print(f"[ENRICH] Analizando {len(ips)} IPs en modo PROFUNDO...")
        print("[ENRICH] Esto puede tomar varios minutos...")

        # Procesar en paralelo con límite de concurrencia
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_ip = {
                executor.submit(enrich_ip_deep, ip, additional_lists, whois_cache): ip
                for ip in ips
            }

            completed = 0
            for future in as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    results[ip] = future.result()
                    completed += 1
                    if completed % 5 == 0:
                        print(f"[ENRICH] Progreso: {completed}/{len(ips)}")
                except Exception as e:
                    results[ip] = {"ip": ip, "error": str(e)}

        # Guardar caché WHOIS
        if whois_cache:
            save_whois_cache(whois_cache)
            print(f"[ENRICH] Caché WHOIS guardada: {len(whois_cache)} entradas")

    return results


# Alias para compatibilidad
def enrich_ip(ip, mode="fast", additional_lists=None):
    """Función de compatibilidad"""
    if mode == "fast":
        return enrich_ip_fast(ip, additional_lists)
    else:
        return enrich_ip_deep(ip, additional_lists, None)


if __name__ == "__main__":
    print("=" * 60)
    print("DESCARGANDO LISTAS ADICIONALES DE AMENAZAS")
    print("=" * 60)

    import requests

    results = download_additional_lists()

    print("\n" + "=" * 60)
    print("RESULTADO")
    print("=" * 60)
    for name, success in results.items():
        status = "✓" if success else "✗"
        print(f"  [{status}] {name}")
