import os
import ipaddress
import json
from modules.config import GEOLITE_DB_PATH, WHITELIST_IP_RANGES

try:
    import maxminddb

    MAXMIND_AVAILABLE = True
except ImportError:
    MAXMIND_AVAILABLE = False

COUNTRY_NAMES = {
    "US": "United States",
    "CN": "China",
    "RU": "Russia",
    "DE": "Germany",
    "FR": "France",
    "GB": "United Kingdom",
    "JP": "Japan",
    "BR": "Brazil",
    "IN": "India",
    "CA": "Canada",
    "AU": "Australia",
    "ES": "Spain",
    "IT": "Italy",
    "KR": "South Korea",
    "NL": "Netherlands",
    "SE": "Sweden",
    "CH": "Switzerland",
    "PL": "Poland",
    "UA": "Ukraine",
    "VN": "Vietnam",
    "SG": "Singapore",
    "HK": "Hong Kong",
    "TW": "Taiwan",
    "AR": "Argentina",
    "MX": "Mexico",
    "CO": "Colombia",
    "CL": "Chile",
    "PE": "Peru",
    "NG": "Nigeria",
    "KE": "Kenya",
    "ZA": "South Africa",
    "EG": "Egypt",
    "AE": "United Arab Emirates",
    "SA": "Saudi Arabia",
    "IL": "Israel",
    "TR": "Turkey",
    "RO": "Romania",
    "CZ": "Czech Republic",
    "HU": "Hungary",
    "GR": "Greece",
    "PT": "Portugal",
    "BE": "Belgium",
    "AT": "Austria",
    "IR": "Iran",
    "IQ": "Iraq",
    "PK": "Pakistan",
    "ID": "Indonesia",
    "MY": "Malaysia",
    "TH": "Thailand",
    "PH": "Philippines",
    "NZ": "New Zealand",
    "NO": "Norway",
    "FI": "Finland",
    "DK": "Denmark",
    "IE": "Ireland",
    "IS": "Iceland",
    "LU": "Luxembourg",
    "MT": "Malta",
    "CY": "Cyprus",
}


class GeoIPLookup:
    def __init__(self, db_path=None):
        self.db_path = db_path or GEOLITE_DB_PATH
        self.reader = None
        self._load_database()

    def _load_database(self):
        if not MAXMIND_AVAILABLE:
            print(
                "[GEOIP] Warning: maxminddb not available. GeoIP lookups will be limited."
            )
            return

        if not os.path.exists(self.db_path):
            print(f"[GEOIP] Database not found at {self.db_path}")
            print("[GEOIP] Download GeoLite2 Country database from:")
            print("[GEOIP]   https://dev.maxmind.com/geoip/geoip2/geolite2/")
            return

        try:
            self.reader = maxminddb.open_database(self.db_path)
            print(f"[GEOIP] Database loaded: {self.db_path}")
        except Exception as e:
            print(f"[GEOIP] Error loading database: {e}")

    def is_private_ip(self, ip_str):
        try:
            ip = ipaddress.ip_address(ip_str)
            return ip.is_private
        except ValueError:
            return False

    def is_whitelisted_range(self, ip_str):
        try:
            ip = ipaddress.ip_address(ip_str)
            for range_str in WHITELIST_IP_RANGES:
                network = ipaddress.ip_network(range_str, strict=False)
                if ip in network:
                    return True
            return False
        except ValueError:
            return False

    def lookup(self, ip_str):
        result = {
            "ip": ip_str,
            "is_private": self.is_private_ip(ip_str),
            "is_whitelisted": self.is_whitelisted_range(ip_str),
            "country": None,
            "country_name": None,
            "asn": None,
            "as_org": None,
            "is_known_service": False,
        }

        if result["is_private"] or result["is_whitelisted"]:
            result["country"] = "LO"
            result["country_name"] = "Local/Private"
            return result

        if not self.reader:
            return result

        try:
            data = self.reader.get(ip_str)
            if data:
                if "country" in data:
                    result["country"] = data["country"].get("iso_code")
                    result["country_name"] = data["country"].get("names", {}).get("en")
                elif "registered_country" in data:
                    result["country"] = data["registered_country"].get("iso_code")
                    result["country_name"] = (
                        data["registered_country"].get("names", {}).get("en")
                    )

                if "asn" in data:
                    result["asn"] = data["asn"]
                if "autonomous_system_number" in data:
                    result["asn"] = data["autonomous_system_number"]

                if "asn" in data:
                    result["as_org"] = data.get("asn_organization") or data.get(
                        "autonomous_system_organization"
                    )

                if not result["country_name"] and result["country"]:
                    result["country_name"] = COUNTRY_NAMES.get(
                        result["country"], result["country"]
                    )

        except Exception as e:
            pass

        return result

    def lookup_batch(self, ip_list):
        results = {}
        for ip in ip_list:
            results[ip] = self.lookup(ip)
        return results

    def close(self):
        if self.reader:
            self.reader.close()


def get_ip_info(ip_str, geoip=None):
    if not geoip:
        geoip = GeoIPLookup()
    return geoip.lookup(ip_str)


def is_ip_private(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private
    except ValueError:
        return False


def is_ip_whitelisted(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
        for range_str in WHITELIST_IP_RANGES:
            network = ipaddress.ip_network(range_str, strict=False)
            if ip in network:
                return True
        return False
    except ValueError:
        return False
