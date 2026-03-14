import threading
import subprocess
import json
import re
import os
import signal
from datetime import datetime
from modules.config import DNS_LOG_FILE, DNS_QUERY_TYPES


class DNSCapture:
    def __init__(self, output_file=None, verbose=True):
        self.output_file = output_file or DNS_LOG_FILE
        self.verbose = verbose
        self.running = False
        self.process = None
        self.queries = []
        self.responses = []
        self._lock = threading.Lock()

    def _parse_dns_query(self, line):
        try:
            timestamp = datetime.now().isoformat()

            query_pattern = r"(\d+\.\d+\.\d+\.\d+)\.(\d+)\s+>\s+(\d+\.\d+\.\d+\.\d+)\.(\d+):\s+(\d+)\+?\s*([A-Z]+)\?(.+?)\."
            match = re.search(query_pattern, line)

            if match:
                src_ip = match.group(1)
                src_port = match.group(2)
                dst_ip = match.group(3)
                dst_port = match.group(4)
                transaction_id = match.group(5)
                query_type = match.group(6).strip()
                domain = match.group(7).strip()

                query_data = {
                    "timestamp": timestamp,
                    "domain": domain,
                    "type": query_type,
                    "src_ip": src_ip,
                    "src_port": src_port,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "transaction_id": transaction_id,
                }
                return query_data
            return None
        except Exception as e:
            if self.verbose:
                print(f"[DNS] Error parsing query: {e}")
            return None

    def _parse_dns_response(self, line):
        try:
            timestamp = datetime.now().isoformat()

            response_pattern = r"(\d+\.\d+\.\d+\.\d+)\.(\d+)\s+>\s+(\d+\.\d+\.\d+\.\d+)\.(\d+):\s+(\d+)\s+([A-Z]+)\s+(.+)"
            match = re.search(response_pattern, line)

            if match:
                src_ip = match.group(1)
                src_port = match.group(2)
                dst_ip = match.group(3)
                dst_port = match.group(4)
                transaction_id = match.group(5)
                query_type = match.group(6)
                answer = match.group(7).strip()

                ip_pattern = r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
                ips = re.findall(ip_pattern, answer)

                response_data = {
                    "timestamp": timestamp,
                    "response_to_transaction": transaction_id,
                    "query_type": query_type,
                    "answers": ips,
                    "raw_answer": answer,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                }
                return response_data
            return None
        except Exception as e:
            if self.verbose:
                print(f"[DNS] Error parsing response: {e}")
            return None

    def _capture_loop(self, interface):
        cmd = ["sudo", "tcpdump", "-i", interface, "-l", "-n", "port", "53", "-v"]

        self.process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1
        )

        if self.verbose:
            print(f"[DNS] Capturing DNS traffic on {interface}...")

        for line in self.process.stdout:
            if not self.running:
                break

            if "Queries" in line or "Query" in line:
                query_data = self._parse_dns_query(line)
                if query_data:
                    with self._lock:
                        self.queries.append(query_data)
                        self._save_to_file()
                    if self.verbose:
                        print(
                            f"[DNS] Query: {query_data['domain']} ({query_data['type']})"
                        )

            elif "Responses" in line or "Response" in line:
                response_data = self._parse_dns_response(line)
                if response_data:
                    with self._lock:
                        self.responses.append(response_data)
                        self._save_to_file()
                    if self.verbose and response_data.get("answers"):
                        print(f"[DNS] Response: {response_data['answers']}")

    def _save_to_file(self):
        try:
            with open(self.output_file, "w") as f:
                json.dump(
                    {
                        "queries": self.queries,
                        "responses": self.responses,
                        "captured_at": datetime.now().isoformat(),
                    },
                    f,
                    indent=2,
                )
        except Exception as e:
            if self.verbose:
                print(f"[DNS] Error saving to file: {e}")

    def start(self, interface="any"):
        if self.running:
            return

        self.running = True
        self.thread = threading.Thread(target=self._capture_loop, args=(interface,))
        self.thread.daemon = True
        self.thread.start()

    def stop(self):
        self.running = False

        # Terminar el proceso de tcpdump
        if self.process:
            self.process.terminate()
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                try:
                    self.process.kill()
                except:
                    pass

        # Guardar datos antes de terminar
        self._save_to_file()

        if self.verbose:
            print(
                f"[DNS] Stopped. Total queries: {len(self.queries)}, responses: {len(self.responses)}"
            )

    def get_data(self):
        with self._lock:
            return {"queries": self.queries.copy(), "responses": self.responses.copy()}

    def get_unique_domains(self):
        with self._lock:
            domains = set(q["domain"] for q in self.queries)
            return list(domains)

    def get_domain_ip_map(self):
        with self._lock:
            domain_ips = {}
            for q in self.queries:
                domain = q["domain"]
                for r in self.responses:
                    if r.get("answers"):
                        if domain not in domain_ips:
                            domain_ips[domain] = set()
                        domain_ips[domain].update(r["answers"])
            return {k: list(v) for k, v in domain_ips.items()}


def clear_dns_cache():
    try:
        result = subprocess.run(
            ["sudo", "resolvectl", "flush-caches"], capture_output=True, text=True
        )
        if result.returncode == 0:
            print("[DNS] Cache cleared successfully")
            return True
    except FileNotFoundError:
        pass

    try:
        result = subprocess.run(
            ["sudo", "systemd-resolve", "--flush-caches"],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            print("[DNS] Cache cleared successfully (systemd-resolve)")
            return True
    except FileNotFoundError:
        pass

    try:
        result = subprocess.run(
            ["sudo", "/etc/init.d/dns-clean", "start"], capture_output=True, text=True
        )
        if result.returncode == 0:
            print("[DNS] Cache cleared successfully (dns-clean)")
            return True
    except FileNotFoundError:
        pass

    print(
        "[DNS] Warning: Could not clear DNS cache. systemd-resolved may not be available."
    )
    return False


def get_network_interfaces():
    try:
        result = subprocess.run(["ip", "link", "show"], capture_output=True, text=True)
        interfaces = []
        for line in result.stdout.split("\n"):
            if ": " in line:
                iface = line.split(": ")[1].split(":")[0]
                if iface != "lo":
                    interfaces.append(iface)
        return interfaces if interfaces else ["any"]
    except Exception:
        return ["any"]


def get_default_interface():
    try:
        result = subprocess.run(
            ["ip", "route", "show", "default"], capture_output=True, text=True
        )
        for line in result.stdout.split("\n"):
            if "default" in line:
                parts = line.split()
                if "dev" in parts:
                    idx = parts.index("dev") + 1
                    return parts[idx]
    except Exception:
        pass
    return "any"
