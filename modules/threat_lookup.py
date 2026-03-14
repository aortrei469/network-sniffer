import os
import json
import ipaddress
from datetime import datetime
from modules.config import (
    THREATFOX_DB_PATH,
    SPAMHAUS_DB_PATH,
    WHITELIST_DOMAINS,
    RISK_LEVELS,
    RISK_THRESHOLDS,
    ALERT_PORTS,
)
from modules.geoip import GeoIPLookup


class ThreatLookup:
    def __init__(self, threatfox_path=None, spamhaus_path=None, geoip=None):
        self.threatfox_path = threatfox_path or THREATFOX_DB_PATH
        self.spamhaus_path = spamhaus_path or SPAMHAUS_DB_PATH
        self.geoip = geoip or GeoIPLookup()

        self.threatfox_ips = set()
        self.spamhaus_ips = set()
        self.spamhaus_ranges = []  # Almacenar rangos en lugar de IPs expandidas

        self._load_databases()

    def _load_databases(self):
        if os.path.exists(self.threatfox_path):
            try:
                with open(self.threatfox_path, "r") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            ip = line.split(",")[0].strip()
                            try:
                                ipaddress.ip_address(ip)
                                self.threatfox_ips.add(ip)
                            except ValueError:
                                pass
                print(f"[THREAT] Loaded {len(self.threatfox_ips)} IPs from ThreatFox")
            except Exception as e:
                print(f"[THREAT] Error loading ThreatFox database: {e}")

        if os.path.exists(self.spamhaus_path):
            try:
                with open(self.spamhaus_path, "r") as f:
                    for line in f:
                        line = line.strip()
                        if (
                            line
                            and not line.startswith(";")
                            and not line.startswith("#")
                        ):
                            parts = line.split(";")
                            if parts:
                                ip_range = parts[0].strip()
                                try:
                                    # Solo almacenar el rango, no expandir todas las IPs
                                    # Esto evita millones de entradas en memoria
                                    network = ipaddress.ip_network(
                                        ip_range, strict=False
                                    )
                                    self.spamhaus_ranges.append(network)
                                except ValueError:
                                    pass
                print(
                    f"[THREAT] Loaded {len(self.spamhaus_ranges)} ranges from Spamhaus"
                )
            except Exception as e:
                print(f"[THREAT] Error loading Spamhaus database: {e}")

    def is_whitelisted_domain(self, domain):
        domain_lower = domain.lower()
        for whitelisted in WHITELIST_DOMAINS:
            if domain_lower == whitelisted or domain_lower.endswith("." + whitelisted):
                return True
        return False

    def is_whitelisted_ip(self, ip_str):
        if self.geoip.is_private_ip(ip_str):
            return True
        if self.geoip.is_whitelisted_range(ip_str):
            return True
        return False

    def check_ip(self, ip_str, domain=None):
        result = {
            "ip": ip_str,
            "domain": domain,
            "risk_level": "unknown",
            "risk_emoji": "🟡",
            "risk_score": 25,
            "description": "IP no encontrada en bases de datos de amenazas",
            "sources": [],
            "geo_info": None,
            "alerts": [],
        }

        if domain and self.is_whitelisted_domain(domain):
            result["risk_level"] = "whitelisted"
            result["risk_emoji"] = "🟢"
            result["risk_score"] = 0
            result["description"] = "Dominio en lista blanca (servicio conocido)"
            result["sources"] = ["whitelist"]
            result["geo_info"] = self.geoip.lookup(ip_str)
            return result

        if self.is_whitelisted_ip(ip_str):
            result["risk_level"] = "safe"
            result["risk_emoji"] = "🟢"
            result["risk_score"] = 0
            result["description"] = "IP privada o en rango conocido"
            result["sources"] = ["private_ip"]
            result["geo_info"] = self.geoip.lookup(ip_str)
            return result

        result["geo_info"] = self.geoip.lookup(ip_str)

        if ip_str in self.threatfox_ips:
            result["risk_level"] = "dangerous"
            result["risk_emoji"] = "🔴"
            result["risk_score"] = 100
            result["description"] = "IP conocida por malware (ThreatFox IOC)"
            result["sources"] = ["threatfox"]
            return result

        # Verificar si IP está en algún rango de Spamhaus
        ip_obj = ipaddress.ip_address(ip_str)
        for network in self.spamhaus_ranges:
            if ip_obj in network:
                result["risk_level"] = "dangerous"
                result["risk_emoji"] = "🔴"
                result["risk_score"] = 100
                result["description"] = (
                    "IP en lista de bloqueo de Spamhaus (DROP/EDROP)"
                )
                result["sources"] = ["spamhaus"]
                return result

        country = result["geo_info"].get("country")
        if country in ["KP", "IR", "SY", "CU", "VE"]:
            result["risk_level"] = "suspicious"
            result["risk_emoji"] = "🟠"
            result["risk_score"] = 50
            result["description"] = f"IP de país con restricciones: {country}"
            result["sources"] = ["country_restricted"]

        return result

    def check_connection(self, ip_str, port=None, sni=None, domain=None):
        result = self.check_ip(ip_str, domain)

        if port and port in ALERT_PORTS:
            result["alerts"].append(
                {
                    "type": "suspicious_port",
                    "port": port,
                    "description": ALERT_PORTS[port],
                    "severity": "high",
                }
            )
            if result["risk_score"] < 75:
                result["risk_score"] = 75
                result["risk_level"] = "dangerous"
                result["risk_emoji"] = "🔴"

        if sni and self.is_whitelisted_domain(sni):
            result["sni_info"] = {"sni": sni, "status": "whitelisted"}
        elif sni:
            result["sni_info"] = {"sni": sni, "status": "unknown"}

        return result

    def check_batch(self, ip_list):
        results = {}
        for ip in ip_list:
            results[ip] = self.check_ip(ip)
        return results

    def get_risk_summary(self, ip_results):
        summary = {
            "total": len(ip_results),
            "safe": 0,
            "whitelisted": 0,
            "unknown": 0,
            "suspicious": 0,
            "dangerous": 0,
            "by_source": {},
            "by_country": {},
        }

        for ip, result in ip_results.items():
            level = result.get("risk_level", "unknown")
            if level == "safe":
                summary["safe"] += 1
            elif level == "whitelisted":
                summary["whitelisted"] += 1
            elif level == "unknown":
                summary["unknown"] += 1
            elif level == "suspicious":
                summary["suspicious"] += 1
            elif level == "dangerous":
                summary["dangerous"] += 1

            for source in result.get("sources", []):
                summary["by_source"][source] = summary["by_source"].get(source, 0) + 1

            country = result.get("geo_info", {}).get("country")
            if country:
                summary["by_country"][country] = (
                    summary["by_country"].get(country, 0) + 1
                )

        return summary


def analyze_connection(ip_str, port=None, sni=None, domain=None, threat_lookup=None):
    if not threat_lookup:
        threat_lookup = ThreatLookup()
    return threat_lookup.check_connection(ip_str, port, sni, domain)
