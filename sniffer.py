#!/usr/bin/env python3
"""
Network Sniffer - Captura y análisis de conexiones de red
"""

import os
import sys
import signal
import argparse
import time
import threading
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.dns_capture import DNSCapture, clear_dns_cache, get_default_interface
from modules.packet_capture import PacketCapture
from modules.config import LOGS_DIR


class NetworkSniffer:
    def __init__(self, interface="any", output_dir=None, verbose=True):
        self.interface = interface
        self.output_dir = output_dir or LOGS_DIR
        self.verbose = verbose

        os.makedirs(self.output_dir, exist_ok=True)

        self.dns_capture = DNSCapture(
            output_file=os.path.join(self.output_dir, "dns_queries.json"),
            verbose=verbose,
        )

        self.packet_capture = PacketCapture(
            output_file=os.path.join(self.output_dir, "connections.json"),
            sni_file=os.path.join(self.output_dir, "tls_sni.json"),
            verbose=verbose,
        )

        self.running = False

    def signal_handler(self, signum, frame):
        print("\n\n[SNIF] Señal de parada recibida...")
        self.running = False
        self.stop()
        sys.exit(0)

    def start(self, duration=None):
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

        print("=" * 60)
        print("       NETWORK SNIFFER v1.0")
        print("=" * 60)
        print()

        print(f"[SNIF] Interfaz: {self.interface}")
        print(f"[SNIF] Directorio de logs: {self.output_dir}")
        print()

        print("[SNIF] Limpiando caché DNS...")
        clear_dns_cache()
        print()

        print("[SNIF] Iniciando captura de tráfico...")
        print("[SNIF] Presiona Ctrl+C para detener y generar informe")
        print()

        self.running = True

        # Iniciar captura DNS en thread separado
        self.dns_capture.start(interface=self.interface)

        # Iniciar captura de paquetes en thread separado
        def start_packets():
            try:
                self.packet_capture.start(interface=self.interface)
            except Exception as e:
                if self.verbose:
                    print(f"[SNIF] Advertencia: Error con scapy: {e}")
                print("[SNIF] Solo se capturara trafico DNS")

        self.packet_thread = threading.Thread(target=start_packets)
        self.packet_thread.daemon = True
        self.packet_thread.start()

        start_time = time.time()

        try:
            while self.running:
                time.sleep(1)

                if duration and (time.time() - start_time) >= duration:
                    print(f"[SNIF] Tiempo de captura completado: {duration}s")
                    break

                if self.verbose and int(time.time() - start_time) % 30 == 0:
                    dns_data = self.dns_capture.get_data()
                    pkt_data = self.packet_capture.get_data()
                    print(
                        f"[SNIF] Stats: DNS={len(dns_data['queries'])} queries, "
                        f"PKT={len(pkt_data['connections'])} conexiones"
                    )

        except KeyboardInterrupt:
            pass
        finally:
            self.stop()

    def stop(self):
        self.running = False

        print("[SNIF] Deteniendo captura DNS...")
        self.dns_capture.stop()

        print("[SNIF] Deteniendo captura de paquetes...")
        self.packet_capture.stop()

        print("\n[SNIF] Captura finalizada!")
        print(f"[SNIF] Logs guardados en: {self.output_dir}")

        dns_data = self.dns_capture.get_data()
        pkt_data = self.packet_capture.get_data()

        print("\n" + "=" * 60)
        print("RESUMEN DE CAPTURA")
        print("=" * 60)
        print(f"  Consultas DNS: {len(dns_data['queries'])}")
        print(f"  Respuestas DNS: {len(dns_data['responses'])}")
        print(f"  Conexiones TCP/UDP: {len(pkt_data['connections'])}")
        print(f"  Handshakes TLS: {len(pkt_data['tls_handshakes'])}")
        print("=" * 60)


def main():
    parser = argparse.ArgumentParser(
        description="Network Sniffer - Captura y analisis de conexiones de red",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos de uso:
  %(prog)s --capture                          Iniciar captura
  %(prog)s --capture -i eth0                  Capturar en interfaz especifica
  %(prog)s --capture -o /tmp/mis_logs         Directorio de salida
  %(prog)s --capture --duration 300           Duracion limitada (5 min)
  %(prog)s --analyze -I logs/                 Analizar logs (modo rapido)
  %(prog)s --analyze -I logs/ -m deep        Analizar logs (modo profundo)
  %(prog)s --analyze -I logs/ -B             Analisis + blocklist auto
  %(prog)s --analyze -I logs/ -B -r 25       Blocklist con threshold 25
  %(prog)s --blocklist -I logs/              Generar blocklists
  %(prog)s --update-db                       Actualizar bases de datos

Modos de uso:
  1. Captura:   %(prog)s --capture [-i interface] [-o directorio]
  2. Analisis:  %(prog)s --analyze -I directorio [-m fast|deep] [-B] [-r threshold]
  3. Blocklist: %(prog)s --blocklist -I directorio [--format ...]
  4. Actualizar: %(prog)s --update-db

Opciones de analisis:
  -m, --analyze-mode  fast|deep   Modo de analisis
  -B, --auto-blocklist           Generar blocklist automaticamente
  -r, --risk-threshold 25|50|75|100  Minimo riesgo para blocklist (default: 50)
        """,
    )

    parser.add_argument(
        "--capture", "-c", action="store_true", help="Iniciar modo captura de tráfico"
    )
    parser.add_argument(
        "--analyze",
        "-a",
        action="store_true",
        help="Analizar logs existentes y generar informe",
    )
    parser.add_argument(
        "--update-db",
        "-u",
        action="store_true",
        help="Actualizar bases de datos de amenazas offline",
    )
    parser.add_argument(
        "--blocklist",
        "-b",
        action="store_true",
        help="Generar blocklists para DNS/firewall",
    )

    parser.add_argument(
        "--interface",
        "-i",
        default="any",
        help="Interfaz de red a capturar (default: any)",
    )
    parser.add_argument(
        "--input",
        "-I",
        default=None,
        help="Directorio de entrada con logs para analizar",
    )
    parser.add_argument(
        "--output",
        "-o",
        default=None,
        help="Directorio de salida para logs, informes o blocklists",
    )
    parser.add_argument(
        "--duration",
        "-d",
        type=int,
        default=None,
        help="Duración de la captura en segundos",
    )
    parser.add_argument(
        "--format",
        "-f",
        nargs="+",
        choices=["mikrotik", "dnsmasq", "iptables", "hosts", "bind", "unbound", "csv"],
        help="Formatos de blocklist a generar",
    )
    parser.add_argument(
        "--analyze-mode",
        "-m",
        choices=["fast", "deep"],
        default="fast",
        help="Modo de analisis: fast (listas) o deep (PTR + WHOIS + listas)",
    )
    parser.add_argument(
        "--auto-blocklist",
        "-B",
        action="store_true",
        help="Generar blocklists automaticamente tras el analisis (para riesgo >= 50)",
    )
    parser.add_argument(
        "--risk-threshold",
        "-r",
        type=int,
        default=50,
        choices=[25, 50, 75, 100],
        help="Nivel de riesgo minimo para blocklist (default: 50)",
    )

    args = parser.parse_args()

    if args.update_db:
        from modules.update_db import update_databases

        update_databases()
        return

    if args.analyze:
        if not args.input:
            print(
                "Error: Se requiere --input/-I para especificar el directorio de logs"
            )
            sys.exit(1)

        from modules.report import generate_report, generate_blocklists

        output_dir = args.output or os.path.join(args.input, "informes")

        print("=" * 60)
        print("       ANALISIS DE LOGS")
        print("=" * 60)
        print(f"  Directorio de logs: {args.input}")
        print(f"  Directorio de informes: {output_dir}")
        print(f"  Modo de analisis: {args.analyze_mode.upper()}")
        print(f"  Threshold blocklist: {args.risk_threshold}")
        print()

        files = generate_report(
            args.input, output_dir, args.analyze_mode, args.risk_threshold
        )

        print("\n" + "=" * 60)
        print("INFORMES GENERADOS")
        print("=" * 60)
        print(f"  Texto: {files['txt']}")
        print(f"  JSON:  {files['json']}")
        print(f"  HTML:  {files['html']}")

        # Generar blocklists automaticamente si se pide
        if args.auto_blocklist:
            print("\n" + "=" * 60)
            print("GENERANDO BLOCKLISTS AUTOMATICAS")
            print("=" * 60)
            blocklist_dir = os.path.join(args.input, "blocklists")
            blocklist_formats = args.format if args.format else None

            bl_files = generate_blocklists(
                args.input, blocklist_dir, blocklist_formats, args.risk_threshold
            )

            for fmt, info in bl_files.items():
                print(f"  {fmt}: {info['count']} IPs -> {info['file']}")

        print("=" * 60)
        return

    if args.blocklist:
        if not args.input:
            print(
                "Error: Se requiere --input/-I para especificar el directorio de logs"
            )
            sys.exit(1)

        from modules.report import generate_blocklists

        output_dir = args.output or os.path.join(args.input, "blocklists")

        print("=" * 60)
        print("       GENERACION DE BLOCKLISTS")
        print("=" * 60)
        print(f"  Directorio de logs: {args.input}")
        print(f"  Directorio de blocklists: {output_dir}")
        if args.format:
            print(f"  Formatos: {', '.join(args.format)}")
        else:
            print(f"  Formatos: todos")
        print()

        files = generate_blocklists(args.input, output_dir, args.format)

        print("\n" + "=" * 60)
        print("BLOCKLISTS GENERADAS")
        print("=" * 60)
        for fmt, info in files.items():
            print(f"  {fmt}: {info['count']} IPs -> {info['file']}")
        print("=" * 60)
        return

    if args.capture:
        sniffer = NetworkSniffer(
            interface=args.interface, output_dir=args.output, verbose=True
        )
        sniffer.start(duration=args.duration)
        return

    parser.print_help()


if __name__ == "__main__":
    main()
