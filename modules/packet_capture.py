import threading
import json
import re
from datetime import datetime
from collections import defaultdict

try:
    from scapy.all import sniff, IP, TCP, UDP, Raw

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    IP = TCP = UDP = Raw = None

try:
    from scapy.layers.tls.handshake import TLSClientHello
except ImportError:
    try:
        from scapy.all import TLSClientHello
    except ImportError:
        TLSClientHello = None

from modules.config import (
    CONNECTIONS_LOG_FILE,
    TLS_SNI_LOG_FILE,
    PROTOCOL_NAMES,
    COMMON_PORTS,
    SUSPICIOUS_PORTS,
)


class PacketCapture:
    def __init__(self, output_file=None, sni_file=None, verbose=True):
        self.output_file = output_file or CONNECTIONS_LOG_FILE
        self.sni_file = sni_file or TLS_SNI_LOG_FILE
        self.verbose = verbose
        self.running = False
        self.connections = []
        self.tls_handshakes = []
        self._lock = threading.Lock()

        self.connection_stats = defaultdict(
            lambda: {
                "count": 0,
                "ports": defaultdict(int),
                "protocols": set(),
                "first_seen": None,
                "last_seen": None,
            }
        )

        self.local_ip = self._get_local_ip()

    def _get_local_ip(self):
        try:
            import socket

            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except Exception:
            return "127.0.0.1"

    def _extract_http_url(self, payload):
        try:
            if isinstance(payload, bytes):
                payload = payload.decode("utf-8", errors="ignore")

            patterns = [
                r"GET\s+(/[^\s]*)\s+HTTP",
                r"POST\s+(/[^\s]*)\s+HTTP",
                r"PUT\s+(/[^\s]*)\s+HTTP",
                r"DELETE\s+(/[^\s]*)\s+HTTP",
                r"HEAD\s+(/[^\s]*)\s+HTTP",
                r"OPTIONS\s+(/[^\s]*)\s+HTTP",
            ]

            for pattern in patterns:
                match = re.search(pattern, payload)
                if match:
                    return match.group(1)

            host_match = re.search(r"Host:\s*([^\s\r\n]+)", payload)
            if host_match:
                return f"Host: {host_match.group(1)}"

            return None
        except Exception:
            return None

    def _extract_tls_sni(self, packet):
        try:
            if TLSClientHello in packet:
                tls_layer = packet[TLSClientHello]
                if hasattr(tls_layer, "ext"):
                    for ext in tls_layer.ext:
                        if hasattr(ext, "servernames"):
                            for sn in ext.servernames:
                                return sn.servername.decode("utf-8", errors="ignore")
            return None
        except Exception:
            return None

    def _process_packet(self, packet):
        try:
            if not packet.haslayer(IP):
                return

            timestamp = datetime.now().isoformat()

            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst

            if src_ip == self.local_ip:
                direction = "outbound"
                remote_ip = dst_ip
            elif dst_ip == self.local_ip:
                direction = "inbound"
                remote_ip = src_ip
            else:
                return

            protocol = PROTOCOL_NAMES.get(ip_layer.proto, str(ip_layer.proto))
            info = {}

            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                sport = tcp_layer.sport
                dport = tcp_layer.dport
                flags = tcp_layer.flags

                info = {
                    "src_port": sport,
                    "dst_port": dport,
                    "flags": str(flags),
                }

                port_name = COMMON_PORTS.get(
                    dport if direction == "outbound" else sport, None
                )
                if port_name:
                    info["port_name"] = port_name

                if dport in SUSPICIOUS_PORTS or sport in SUSPICIOUS_PORTS:
                    info["suspicious_port"] = SUSPICIOUS_PORTS.get(
                        dport, SUSPICIOUS_PORTS.get(sport)
                    )

                if packet.haslayer(Raw) and (
                    port_name == "HTTP" or dport == 80 or sport == 80
                ):
                    payload = bytes(packet[Raw].load)
                    url = self._extract_http_url(payload[:500])
                    if url:
                        info["url"] = url

            elif packet.haslayer(UDP):
                udp_layer = packet[UDP]
                sport = udp_layer.sport
                dport = udp_layer.dport

                info = {
                    "src_port": sport,
                    "dst_port": dport,
                }

                if dport == 53 or sport == 53:
                    return

            sni = None
            if packet.haslayer(TCP):
                try:
                    tcp_layer = packet[TCP]
                    if tcp_layer.dport == 443 or tcp_layer.sport == 443:
                        sni = self._extract_tls_sni(packet)
                        if sni:
                            with self._lock:
                                self.tls_handshakes.append(
                                    {
                                        "timestamp": timestamp,
                                        "sni": sni,
                                        "src_ip": src_ip,
                                        "dst_ip": dst_ip,
                                    }
                                )
                                self._save_tls_file()
                except (AttributeError, IndexError):
                    pass

            conn_data = {
                "timestamp": timestamp,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "direction": direction,
                "protocol": protocol,
                "info": info,
                "sni": sni,
            }

            with self._lock:
                self.connections.append(conn_data)

                if remote_ip:
                    stats = self.connection_stats[remote_ip]
                    stats["count"] += 1
                    port_key = info.get("dst_port") or info.get("src_port")
                    if port_key:
                        stats["ports"][port_key] += 1
                    stats["protocols"].add(protocol)
                    if not stats["first_seen"]:
                        stats["first_seen"] = timestamp
                    stats["last_seen"] = timestamp

                self._save_connections_file()

            if self.verbose:
                port_info = (
                    f":{info.get('dst_port', '')}" if info.get("dst_port") else ""
                )
                sni_info = f" [SNI: {sni}]" if sni else ""
                print(
                    f"[PKT] {direction.upper()}: {src_ip} -> {dst_ip}{port_info} ({protocol}){sni_info}"
                )

        except Exception as e:
            if self.verbose:
                print(f"[PKT] Error processing packet: {e}")

    def _save_connections_file(self):
        try:
            # Convertir defaultdict a dict normal con tipos serializables
            def convert_stats(stats_dict):
                result = {}
                for ip, data in stats_dict.items():
                    result[ip] = {
                        "count": data.get("count", 0),
                        "ports": dict(data.get("ports", {})),
                        "protocols": list(data.get("protocols", set())),
                        "first_seen": data.get("first_seen"),
                        "last_seen": data.get("last_seen"),
                    }
                return result

            with open(self.output_file, "w") as f:
                json.dump(
                    {
                        "connections": self.connections,
                        "stats": convert_stats(self.connection_stats),
                        "captured_at": datetime.now().isoformat(),
                    },
                    f,
                    indent=2,
                    default=str,
                )
        except Exception as e:
            if self.verbose:
                print(f"[PKT] Error saving connections: {e}")

    def _save_tls_file(self):
        try:
            with open(self.sni_file, "w") as f:
                json.dump(
                    {
                        "handshakes": self.tls_handshakes,
                        "captured_at": datetime.now().isoformat(),
                    },
                    f,
                    indent=2,
                )
        except Exception as e:
            if self.verbose:
                print(f"[PKT] Error saving TLS: {e}")

    def start(self, interface="any", filter_str="", timeout=None):
        if not SCAPY_AVAILABLE:
            print(
                "[PKT] ERROR: Scapy is not available. Install with: pip install scapy"
            )
            return

        if self.running:
            return

        self.running = True

        try:
            self.sniffer = sniff(
                iface=interface if interface != "any" else None,
                filter=filter_str if filter_str else "ip",
                prn=self._process_packet,
                store=False,
                stop_filter=lambda x: not self.running,
            )
        except Exception as e:
            if self.verbose:
                print(f"[PKT] Error starting sniffer: {e}")
            self.running = False

    def stop(self):
        self.running = False

        # Guardar datos antes de terminar
        self._save_connections_file()
        self._save_tls_file()

        if self.verbose:
            print(
                f"[PKT] Stopped. Total connections: {len(self.connections)}, TLS handshakes: {len(self.tls_handshakes)}"
            )

    def get_data(self):
        with self._lock:
            return {
                "connections": self.connections.copy(),
                "tls_handshakes": self.tls_handshakes.copy(),
                "stats": dict(self.connection_stats),
            }

    def get_connection_stats(self):
        with self._lock:
            return dict(self.connection_stats)

    def get_unique_ips(self):
        with self._lock:
            ips = set()
            for conn in self.connections:
                if conn.get("dst_ip") != self.local_ip:
                    ips.add(conn["dst_ip"])
                if conn.get("src_ip") != self.local_ip:
                    ips.add(conn["src_ip"])
            return list(ips)
