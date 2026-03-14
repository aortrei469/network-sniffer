import os
import json
import html
from datetime import datetime
from collections import Counter
from modules.config import COMMON_PORTS, SUSPICIOUS_PORTS, ALERT_PORTS
from modules.geoip import GeoIPLookup, COUNTRY_NAMES
from modules.threat_lookup import ThreatLookup


class ReportGenerator:
    def __init__(self, output_dir="reports"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

        self.geoip = GeoIPLookup()
        self.threat_lookup = ThreatLookup(geoip=self.geoip)

    def load_logs(self, logs_dir):
        dns_file = os.path.join(logs_dir, "dns_queries.json")
        conn_file = os.path.join(logs_dir, "connections.json")
        tls_file = os.path.join(logs_dir, "tls_sni.json")

        data = {
            "dns_queries": [],
            "dns_responses": [],
            "connections": [],
            "tls_handshakes": [],
            "connection_stats": {},
        }

        if os.path.exists(dns_file):
            try:
                with open(dns_file, "r") as f:
                    dns_data = json.load(f)
                    data["dns_queries"] = dns_data.get("queries", [])
                    data["dns_responses"] = dns_data.get("responses", [])
            except Exception as e:
                print(f"Error loading DNS logs: {e}")

        if os.path.exists(conn_file):
            try:
                with open(conn_file, "r") as f:
                    conn_data = json.load(f)
                    data["connections"] = conn_data.get("connections", [])
                    data["connection_stats"] = conn_data.get("stats") or {}
            except Exception as e:
                print(f"Error loading connection logs: {e}")

        if os.path.exists(tls_file):
            try:
                with open(tls_file, "r") as f:
                    tls_data = json.load(f)
                    data["tls_handshakes"] = tls_data.get("handshakes", [])
            except Exception as e:
                print(f"Error loading TLS logs: {e}")

        return data

    def generate_dns_report(self, dns_queries, dns_responses):
        report = []
        report.append("=" * 70)
        report.append("INFORME DE CONSULTAS DNS")
        report.append("=" * 70)
        report.append("")

        domain_counter = Counter()
        query_type_counter = Counter()

        for query in dns_queries:
            domain = query.get("domain", "unknown")
            qtype = query.get("type", "UNKNOWN")
            domain_counter[domain] += 1
            query_type_counter[qtype] += 1

        report.append(f"Total de consultas DNS: {len(dns_queries)}")
        report.append(f"Dominios únicos consultados: {len(domain_counter)}")
        report.append("")

        report.append("--- Dominios más consultados (top 20) ---")
        for domain, count in domain_counter.most_common(20):
            report.append(f"  {count:4d}x  {domain}")

        report.append("")
        report.append("--- Tipos de consulta ---")
        for qtype, count in query_type_counter.most_common():
            report.append(f"  {qtype:6s}: {count}")

        report.append("")
        report.append("--- Respuestas DNS (IPs resueltas) ---")

        domain_ips = {}
        for response in dns_responses:
            for query in dns_queries:
                if query.get("transaction_id") == response.get(
                    "response_to_transaction"
                ):
                    domain = query.get("domain")
                    if domain:
                        if domain not in domain_ips:
                            domain_ips[domain] = set()
                        for ip in response.get("answers", []):
                            domain_ips[domain].add(ip)

        for domain, ips in sorted(domain_ips.items()):
            report.append(f"  {domain}")
            for ip in ips:
                report.append(f"       -> {ip}")

        return "\n".join(report)

    def generate_connections_report(self, connections, connection_stats):
        report = []
        report.append("")
        report.append("=" * 70)
        report.append("INFORME DE CONEXIONES DE RED")
        report.append("=" * 70)
        report.append("")

        report.append(f"Total de conexiones capturadas: {len(connections)}")
        report.append(f"IPs únicas destino: {len(connection_stats)}")
        report.append("")

        sorted_stats = sorted(
            connection_stats.items(), key=lambda x: x[1].get("count", 0), reverse=True
        )

        report.append("--- Conexiones por IP (top 30) ---")
        for ip, stats in sorted_stats[:30]:
            count = stats.get("count", 0)
            ports = stats.get("ports", {})
            protocols = stats.get("protocols", set())

            geo_info = self.geoip.lookup(ip)
            country = (
                geo_info.get("country_name") or geo_info.get("country") or "Unknown"
            )

            port_str = ", ".join(
                [
                    f"{p}:{c}"
                    for p, c in sorted(ports.items(), key=lambda x: x[1], reverse=True)[
                        :3
                    ]
                ]
            )
            if len(ports) > 3:
                port_str += f" (+{len(ports) - 3} más)"

            report.append(f"  {ip} ({country})")
            report.append(f"       Conexiones: {count}")
            report.append(f"       Puertos: {port_str}")
            report.append(f"       Protocolos: {', '.join(protocols)}")
            report.append("")

        return "\n".join(report)

    def generate_threat_analysis(
        self, connections, connection_stats, dns_queries, dns_responses
    ):
        report = []
        report.append("")
        report.append("=" * 70)
        report.append("ANALISIS DE PELIGROSIDAD")
        report.append("=" * 70)
        report.append("")

        domain_ips = {}
        for response in dns_responses:
            for query in dns_queries:
                if query.get("transaction_id") == response.get(
                    "response_to_transaction"
                ):
                    domain = query.get("domain")
                    if domain:
                        if domain not in domain_ips:
                            domain_ips[domain] = set()
                        for ip in response.get("answers", []):
                            domain_ips[domain].add(ip)

        # Obtener IPs de stats o de las conexiones directamente
        all_ips = set()

        # Primero de connection_stats
        if connection_stats:
            all_ips.update(connection_stats.keys())

        # También de las conexiones directamente (fallback)
        for conn in connections:
            if conn.get("dst_ip"):
                all_ips.add(conn["dst_ip"])
            if conn.get("src_ip"):
                all_ips.add(conn["src_ip"])

        # Añadir IPs de DNS
        for ips in domain_ips.values():
            all_ips.update(ips)

        threat_results = {}
        for ip in all_ips:
            domain = None
            for d, ips in domain_ips.items():
                if ip in ips:
                    domain = d
                    break

            port = None
            if connection_stats and ip in connection_stats:
                ports = connection_stats[ip].get("ports", {})
                if ports:
                    port = max(ports.items(), key=lambda x: x[1])[0]

            sni = None

            threat_results[ip] = self.threat_lookup.check_connection(
                ip, port, sni, domain
            )

        summary = self.threat_lookup.get_risk_summary(threat_results)

        report.append(f"Total de IPs analizadas: {summary['total']}")
        report.append(
            f"  🟢 Seguras/Lista blanca: {summary['safe'] + summary['whitelisted']}"
        )
        report.append(f"  🟡 Desconocidas: {summary['unknown']}")
        report.append(f"  🟠 Sospechosas: {summary['suspicious']}")
        report.append(f"  🔴 Peligrosas: {summary['dangerous']}")
        report.append("")

        if summary["by_source"]:
            report.append("--- Fuentes de detección ---")
            for source, count in sorted(
                summary["by_source"].items(), key=lambda x: x[1], reverse=True
            ):
                report.append(f"  {source}: {count}")
            report.append("")

        if summary["by_country"]:
            report.append("--- Distribución por país ---")
            country_names = []
            for country, count in sorted(
                summary["by_country"].items(), key=lambda x: x[1], reverse=True
            )[:10]:
                name = COUNTRY_NAMES.get(country, country)
                country_names.append(f"{name}: {count}")
            report.append("  " + ", ".join(country_names))
            report.append("")

        dangerous_ips = {
            ip: r
            for ip, r in threat_results.items()
            if r["risk_level"] in ["suspicious", "dangerous"]
        }

        if dangerous_ips:
            report.append("--- IPs PELIGROSAS/SOSPECHOSAS ---")
            for ip, result in sorted(
                dangerous_ips.items(), key=lambda x: x[1]["risk_score"], reverse=True
            ):
                report.append(f"  {result['risk_emoji']} {ip}")
                report.append(
                    f"      Nivel: {result['risk_level']} (score: {result['risk_score']})"
                )
                report.append(f"      Descripción: {result['description']}")
                if result.get("geo_info"):
                    geo = result["geo_info"]
                    report.append(
                        f"      Ubicación: {geo.get('country_name') or geo.get('country')}"
                    )
                    if geo.get("asn"):
                        report.append(
                            f"      ASN: {geo['asn']} ({geo.get('as_org', 'N/A')})"
                        )
                if result.get("alerts"):
                    for alert in result["alerts"]:
                        report.append(f"      ⚠️ ALERTA: {alert['description']}")
                if result.get("domain"):
                    report.append(f"      Dominio: {result['domain']}")
                report.append("")

        unknown_ips = {
            ip: r for ip, r in threat_results.items() if r["risk_level"] == "unknown"
        }

        if unknown_ips:
            report.append(f"--- IPs Desconocidas (top 20) ---")
            for ip, result in list(unknown_ips.items())[:20]:
                geo = result.get("geo_info", {})
                country = geo.get("country_name") or geo.get("country") or "?"
                as_info = f" ({geo.get('asn', '')})" if geo.get("asn") else ""
                report.append(f"  🟡 {ip} - {country}{as_info}")
                if result.get("domain"):
                    report.append(f"      Dominio: {result['domain']}")

        return "\n".join(report), threat_results

    def generate_full_report(self, logs_dir, analyze_mode="fast", risk_threshold=50):
        self.risk_threshold = risk_threshold
        print("Cargando datos...")
        data = self.load_logs(logs_dir)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        print("Generando informe de DNS...")
        dns_report = self.generate_dns_report(
            data["dns_queries"], data["dns_responses"]
        )

        print("Generando informe de conexiones...")
        connections_report = self.generate_connections_report(
            data["connections"], data["connection_stats"]
        )

        print(f"Analizando amenazas (modo {analyze_mode})...")
        threat_report, threat_results = self.generate_threat_analysis(
            data["connections"],
            data["connection_stats"],
            data["dns_queries"],
            data["dns_responses"],
        )

        # Enriquecimiento adicional en modo deep
        enrichment_results = {}
        if analyze_mode == "deep":
            try:
                from modules.ip_enrichment import (
                    load_additional_lists,
                    load_whois_cache,
                    analyze_ips_batch,
                )

                print("Cargando listas adicionales...")
                additional_lists = load_additional_lists()
                whois_cache = load_whois_cache()

                # Obtener lista de IPs únicas para enriquecer
                all_ips = set()

                # De connection_stats
                if data.get("connection_stats"):
                    all_ips.update(data["connection_stats"].keys())

                # De las conexiones directamente
                for conn in data.get("connections", []):
                    if conn.get("dst_ip"):
                        all_ips.add(conn["dst_ip"])
                    if conn.get("src_ip"):
                        all_ips.add(conn["src_ip"])

                all_ips = list(all_ips)
                print(f"[ENRICH] Analizando {len(all_ips)} IPs en modo PROFUNDO...")
                enrichment_results = analyze_ips_batch(
                    all_ips,
                    mode="deep",
                    additional_lists=additional_lists,
                    whois_cache=whois_cache,
                )

                # Actualizar threat_results con enriquecimiento
                for ip, enrichment in enrichment_results.items():
                    if ip in threat_results:
                        threat_results[ip]["enrichment"] = enrichment

                        # Actualizar nivel de riesgo si hay factores
                        if enrichment.get("risk_factors"):
                            for factor in enrichment["risk_factors"]:
                                threat_results[ip]["risk_factors"] = threat_results[
                                    ip
                                ].get("risk_factors", [])
                                threat_results[ip]["risk_factors"].append(factor)

                            # Aumentar score si hay factores de riesgo
                            if enrichment["risk_factors"]:
                                threat_results[ip]["risk_score"] = min(
                                    100, threat_results[ip]["risk_score"] + 25
                                )
                                if threat_results[ip]["risk_score"] >= 50:
                                    threat_results[ip]["risk_level"] = "dangerous"
                                    threat_results[ip]["risk_emoji"] = "🔴"

            except Exception as e:
                print(f"[WARN] Error en enriquecimiento: {e}")

        full_report = []
        full_report.append(
            f"INFORME DE ANALISIS DE RED - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )
        full_report.append("=" * 70)
        if analyze_mode == "deep":
            full_report.append("MODO: PROFUNDO (PTR + WHOIS + Listas adicionales)")
        else:
            full_report.append("MODO: RAPIDO (Solo listas de amenazas)")
        full_report.append("")
        full_report.append(dns_report)
        full_report.append(connections_report)
        full_report.append(threat_report)

        # Añadir sección de enriquecimiento en modo deep
        if analyze_mode == "deep" and enrichment_results:
            full_report.append("")
            full_report.append("=" * 70)
            full_report.append("ENRIQUECIMIENTO WHOIS/PTR (Modo Profundo)")
            full_report.append("=" * 70)

            for ip, enrich in enrichment_results.items():
                if (
                    enrich.get("ptr")
                    or enrich.get("whois")
                    or enrich.get("risk_factors")
                ):
                    full_report.append(f"\n{ip}:")
                    if enrich.get("ptr"):
                        full_report.append(f"  PTR: {enrich['ptr']}")
                    if enrich.get("organization"):
                        full_report.append(f"  Org: {enrich['organization']}")
                    if enrich.get("country"):
                        full_report.append(f"  Pais: {enrich['country']}")
                    if enrich.get("asn"):
                        full_report.append(f"  ASN: {enrich['asn']}")
                    if enrich.get("risk_factors"):
                        for factor in enrich["risk_factors"]:
                            full_report.append(f"  ! {factor}")

        full_report_text = "\n".join(full_report)

        txt_file = os.path.join(self.output_dir, f"informe_{timestamp}.txt")
        with open(txt_file, "w") as f:
            f.write(full_report_text)

        print(f"Informe guardado: {txt_file}")

        json_data = {
            "generated_at": datetime.now().isoformat(),
            "logs_dir": logs_dir,
            "analyze_mode": analyze_mode,
            "summary": {
                "total_dns_queries": len(data["dns_queries"]),
                "total_connections": len(data["connections"]),
                "unique_ips": len(data["connection_stats"]),
            },
            "dns_queries": data["dns_queries"],
            "dns_responses": data["dns_responses"],
            "connections": data["connections"],
            "tls_handshakes": data["tls_handshakes"],
            "connection_stats": data["connection_stats"],
            "threat_analysis": threat_results,
        }

        json_file = os.path.join(self.output_dir, f"informe_{timestamp}.json")
        with open(json_file, "w") as f:
            json.dump(json_data, f, indent=2, default=str)

        print(f"Informe JSON guardado: {json_file}")

        html_file = self.generate_html_report(json_data, timestamp)

        return {"txt": txt_file, "json": json_file, "html": html_file}

    def generate_html_report(self, json_data, timestamp):
        html_content = f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Informe de Análisis de Red - {timestamp}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #1a1a2e; color: #eee; padding: 20px; }}
        .container {{ max-width: 1400px; margin: 0 auto; }}
        h1 {{ color: #00d9ff; text-align: center; margin-bottom: 10px; }}
        .subtitle {{ text-align: center; color: #888; margin-bottom: 30px; }}
        .card {{ background: #16213e; border-radius: 10px; padding: 20px; margin-bottom: 20px; }}
        .card h2 {{ color: #00d9ff; border-bottom: 2px solid #0f3460; padding-bottom: 10px; margin-bottom: 15px; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; }}
        .stat-box {{ background: #0f3460; padding: 15px; border-radius: 8px; text-align: center; }}
        .stat-box .number {{ font-size: 2em; color: #00d9ff; }}
        .stat-box .label {{ color: #888; font-size: 0.9em; }}
        .risk-safe {{ color: #00ff00; }}
        .risk-unknown {{ color: #ffff00; }}
        .risk-suspicious {{ color: #ff9900; }}
        .risk-dangerous {{ color: #ff0000; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #0f3460; }}
        th {{ background: #0f3460; color: #00d9ff; }}
        tr:hover {{ background: #1f2f50; }}
        .badge {{ padding: 3px 8px; border-radius: 4px; font-size: 0.8em; }}
        .badge-safe {{ background: #006400; color: #00ff00; }}
        .badge-unknown {{ background: #666600; color: #ffff00; }}
        .badge-suspicious {{ background: #664400; color: #ff9900; }}
        .badge-dangerous {{ background: #640000; color: #ff0000; }}
        .alert {{ background: #640000; border-left: 4px solid #ff0000; padding: 10px; margin: 5px 0; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ Informe de Análisis de Red</h1>
        <p class="subtitle">Generado: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        
        <div class="card">
            <h2>📊 Estadísticas</h2>
            <div class="stats">
                <div class="stat-box">
                    <div class="number">{json_data["summary"]["total_dns_queries"]}</div>
                    <div class="label">Consultas DNS</div>
                </div>
                <div class="stat-box">
                    <div class="number">{json_data["summary"]["total_connections"]}</div>
                    <div class="label">Conexiones</div>
                </div>
                <div class="stat-box">
                    <div class="number">{json_data["summary"]["unique_ips"]}</div>
                    <div class="label">IPs Únicas</div>
                </div>
            </div>
        </div>
        
        <div class="card">
            <h2>🌐 Análisis de Amenazas</h2>
"""

        threat_results = json_data.get("threat_analysis", {})
        threat_summary = {
            "safe": 0,
            "whitelisted": 0,
            "unknown": 0,
            "suspicious": 0,
            "dangerous": 0,
        }

        for ip, result in threat_results.items():
            level = result.get("risk_level", "unknown")
            threat_summary[level] = threat_summary.get(level, 0) + 1

        html_content += f"""
            <div class="stats">
                <div class="stat-box">
                    <div class="number risk-safe">{threat_summary.get("safe", 0) + threat_summary.get("whitelisted", 0)}</div>
                    <div class="label">Seguras</div>
                </div>
                <div class="stat-box">
                    <div class="number risk-unknown">{threat_summary.get("unknown", 0)}</div>
                    <div class="label">Desconocidas</div>
                </div>
                <div class="stat-box">
                    <div class="number risk-suspicious">{threat_summary.get("suspicious", 0)}</div>
                    <div class="label">Sospechosas</div>
                </div>
                <div class="stat-box">
                    <div class="number risk-dangerous">{threat_summary.get("dangerous", 0)}</div>
                    <div class="label">Peligrosas</div>
                </div>
            </div>
        </div>
        
        <div class="card">
            <h2>🚨 IPs con Alertas</h2>
"""

        alert_ips = [
            (ip, r)
            for ip, r in threat_results.items()
            if r.get("risk_level") in ["suspicious", "dangerous"] or r.get("alerts")
        ]

        if alert_ips:
            html_content += """
            <table>
                <tr>
                    <th>IP</th>
                    <th>Nivel</th>
                    <th>Descripción</th>
                    <th>Ubicación</th>
                    <th>Alertas</th>
                </tr>
"""
            for ip, result in sorted(
                alert_ips, key=lambda x: x[1].get("risk_score", 0), reverse=True
            ):
                risk_class = f"badge-{result.get('risk_level', 'unknown')}"
                geo = result.get("geo_info", {})
                location = geo.get("country_name") or geo.get("country") or "?"

                alerts_html = ""
                for alert in result.get("alerts", []):
                    alerts_html += f"<div class='alert'>{html.escape(alert.get('description', ''))}</div>"

                html_content += f"""
                <tr>
                    <td>{html.escape(ip)}</td>
                    <td><span class="badge {risk_class}">{result.get("risk_emoji", "")} {html.escape(result.get("risk_level", "unknown"))}</span></td>
                    <td>{html.escape(result.get("description", ""))}</td>
                    <td>{html.escape(location)}</td>
                    <td>{alerts_html}</td>
                </tr>
"""
            html_content += "</table>"
        else:
            html_content += "<p>No se encontraron IPs con alertas.</p>"

        html_content += """
        </div>
        
        <div class="card">
            <h2>📝 Todas las IPs Analizadas</h2>
"""

        html_content += """
            <table>
                <tr>
                    <th>IP</th>
                    <th>Nivel de Riesgo</th>
                    <th>País</th>
                    <th>ASN</th>
                    <th>Dominio</th>
                </tr>
"""

        for ip, result in sorted(
            threat_results.items(),
            key=lambda x: x[1].get("risk_score", 0),
            reverse=True,
        ):
            risk_class = f"badge-{result.get('risk_level', 'unknown')}"
            geo = result.get("geo_info", {})
            country = geo.get("country_name") or geo.get("country") or "-"
            asn = geo.get("asn") or "-"
            domain = result.get("domain") or "-"

            html_content += f"""
                <tr>
                    <td>{html.escape(ip)}</td>
                    <td><span class="badge {risk_class}">{result.get("risk_emoji", "")} {result.get("risk_score", 0)}</span></td>
                    <td>{html.escape(country)}</td>
                    <td>{html.escape(str(asn))}</td>
                    <td>{html.escape(domain)}</td>
                </tr>
"""

        html_content += """
            </table>
        </div>
        
        <div class="card">
            <h2>🔗 Conexiones por IP</h2>
"""

        stats = json_data.get("connection_stats", {})
        html_content += """
            <table>
                <tr>
                    <th>IP</th>
                    <th>Conexiones</th>
                    <th>Puerto Principal</th>
                    <th>Protocolos</th>
                </tr>
"""

        for ip, stat in sorted(
            stats.items(), key=lambda x: x[1].get("count", 0), reverse=True
        )[:50]:
            count = stat.get("count", 0)
            ports = stat.get("ports", {})
            main_port = max(ports.items(), key=lambda x: x[1])[0] if ports else "-"
            protocols = ", ".join(stat.get("protocols", set()))

            html_content += f"""
                <tr>
                    <td>{html.escape(ip)}</td>
                    <td>{count}</td>
                    <td>{main_port}</td>
                    <td>{html.escape(protocols)}</td>
                </tr>
"""

        html_content += """
            </table>
        </div>
        
        <div class="card">
            <h2>🌍 Distribución por País</h2>
"""

        country_counts = {}
        for ip, result in threat_results.items():
            geo = result.get("geo_info", {})
            country = geo.get("country") or "UNKNOWN"
            country_counts[country] = country_counts.get(country, 0) + 1

        html_content += """
            <table>
                <tr>
                    <th>País</th>
                    <th>Cantidad</th>
                </tr>
"""

        for country, count in sorted(
            country_counts.items(), key=lambda x: x[1], reverse=True
        ):
            country_name = COUNTRY_NAMES.get(country, country)
            html_content += f"""
                <tr>
                    <td>{html.escape(country_name)} ({country})</td>
                    <td>{count}</td>
                </tr>
"""

        html_content += """
            </table>
        </div>
        
        <footer style="text-align: center; padding: 20px; color: #666;">
            <p>Generado por Network Sniffer v1.0</p>
        </footer>
    </div>
</body>
</html>
"""

        html_file = os.path.join(self.output_dir, f"informe_{timestamp}.html")
        with open(html_file, "w") as f:
            f.write(html_content)

        print(f"Informe HTML guardado: {html_file}")

        return html_file


def generate_report(
    logs_dir, output_dir="reports", analyze_mode="fast", risk_threshold=50
):
    generator = ReportGenerator(output_dir)
    return generator.generate_full_report(logs_dir, analyze_mode, risk_threshold)


class BlocklistGenerator:
    def __init__(self, output_dir="blocklists"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

        self.geoip = GeoIPLookup()
        self.threat_lookup = ThreatLookup(geoip=self.geoip)

    def load_logs(self, logs_dir):
        dns_file = os.path.join(logs_dir, "dns_queries.json")
        conn_file = os.path.join(logs_dir, "connections.json")

        data = {
            "dns_queries": [],
            "dns_responses": [],
            "connections": [],
            "connection_stats": {},
        }

        if os.path.exists(dns_file):
            try:
                with open(dns_file, "r") as f:
                    dns_data = json.load(f)
                    data["dns_queries"] = dns_data.get("queries", [])
                    data["dns_responses"] = dns_data.get("responses", [])
            except Exception as e:
                print(f"Error loading DNS logs: {e}")

        if os.path.exists(conn_file):
            try:
                with open(conn_file, "r") as f:
                    conn_data = json.load(f)
                    data["connections"] = conn_data.get("connections", [])
                    data["connection_stats"] = conn_data.get("stats", {})
            except Exception as e:
                print(f"Error loading connection logs: {e}")

        return data

    def get_all_ips_with_risk(self, data):
        domain_ips = {}
        for response in data["dns_responses"]:
            for query in data["dns_queries"]:
                if query.get("transaction_id") == response.get(
                    "response_to_transaction"
                ):
                    domain = query.get("domain")
                    if domain:
                        if domain not in domain_ips:
                            domain_ips[domain] = set()
                        for ip in response.get("answers", []):
                            domain_ips[domain].add(ip)

        # Obtener IPs de stats o de las conexiones directamente
        all_ips = set()

        # Primero de connection_stats
        if data.get("connection_stats"):
            all_ips.update(data["connection_stats"].keys())

        # También de las conexiones directamente (fallback)
        for conn in data.get("connections", []):
            if conn.get("dst_ip"):
                all_ips.add(conn["dst_ip"])
            if conn.get("src_ip"):
                all_ips.add(conn["src_ip"])

        # Añadir IPs de DNS
        for ips in domain_ips.values():
            all_ips.update(ips)

        threat_results = {}
        for ip in all_ips:
            domain = None
            for d, ips in domain_ips.items():
                if ip in ips:
                    domain = d
                    break

            port = None
            if data.get("connection_stats") and ip in data["connection_stats"]:
                ports = data["connection_stats"][ip].get("ports", {})
                if ports:
                    port = max(ports.items(), key=lambda x: x[1])[0]

            threat_results[ip] = self.threat_lookup.check_connection(
                ip, port, None, domain
            )

        return threat_results

    def generate_bind_zone_file(self, ips_data, output_file, zone_name="block.local"):
        content = f"""; ============================================================
; Blocklist generada por Network Sniffer
; Fecha: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
; Total de dominios/IPs bloqueadas: {len(ips_data)}
; ============================================================

$TTL 86400
@       IN      SOA     ns1.{zone_name}. root.{zone_name}. (
                        {datetime.now().strftime("%Y%m%d%H")}01  ; Serial (YYYYMMDDHH)
                        3600            ; Refresh
                        1800            ; Retry
                        604800          ; Expire
                        86400 )         ; Minimum TTL

; Nameservers
@       IN      NS      ns1.{zone_name}.
ns1     IN      A       127.0.0.1

"""

        blocked_count = 0
        for ip, result in ips_data.items():
            if result["risk_level"] in ["suspicious", "dangerous"]:
                blocked_count += 1
                reason = result.get("description", "").replace(" ", "_")
                content += (
                    f"; {result['risk_emoji']} {result['risk_level']}: {reason}\n"
                )
                content += f"{ip}    IN    A    127.0.0.1\n"
                content += f"{ip}    IN    AAAA    ::1\n\n"

        with open(output_file, "w") as f:
            f.write(content)

        return blocked_count

    def generate_dnsmasq_conf(self, ips_data, output_file):
        content = f"""# ============================================================
# Blocklist generada por Network Sniffer
# Fecha: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
# Total de IPs bloqueadas: {len(ips_data)}
# ============================================================

# Instrucciones de uso:
# 1. Copiar este archivo a /etc/dnsmasq.d/blocklist.conf
# 2. Reiniciar dnsmasq: sudo systemctl restart dnsmasq

"""

        blocked_count = 0
        for ip, result in ips_data.items():
            if result["risk_level"] in ["suspicious", "dangerous"]:
                blocked_count += 1
                content += f"# {result['risk_emoji']} {result['risk_level']}: {result.get('description', '')}\n"
                content += f"address=/{ip}/127.0.0.1\n"

        with open(output_file, "w") as f:
            f.write(content)

        return blocked_count

    def generate_mikrotik_script(self, ips_data, output_file):
        content = f"""# ============================================================
# Blocklist para MikroTik RouterOS
# Generada por Network Sniffer
# Fecha: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
# Total de IPs a bloquear: {len(ips_data)}
# ============================================================

# Instrucciones de uso:
# 1. Abrir Winbox o WebFig
# 2. Ir a System > Scripts
# 3. Crear nuevo script y pegar este contenido
# 4. O ejecutar desde terminal: /import blocklist.rsc

# Limpiar bloqueos anteriores
/ip firewall address-list remove [find list=blocklist-sniffer]

"""

        blocked_count = 0
        for ip, result in ips_data.items():
            if result["risk_level"] in ["suspicious", "dangerous"]:
                blocked_count += 1
                reason = result.get("description", "").replace('"', '\\"')[:50]
                content += f'/ip firewall address-list add list=blocklist-sniffer address={ip} comment="{result["risk_emoji"]} {result["risk_level"]}: {reason}"\n'

        content += f"""
# Regla de firewall para bloquear (descomentar si se necesita)
# /ip firewall filter add chain=forward src-address-list=blocklist-sniffer action=drop comment="Block malicious IPs from Sniffer"
# /ip firewall filter add chain=input src-address-list=blocklist-sniffer action=drop comment="Block malicious IPs from Sniffer"

:log info "Blocklist importada: {blocked_count} IPs peligrosas bloqueadas"
"""

        with open(output_file, "w") as f:
            f.write(content)

        return blocked_count

    def generate_iptables_script(self, ips_data, output_file):
        content = f"""#!/bin/bash
# ============================================================
# Blocklist para iptables
# Generada por Network Sniffer
# Fecha: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
# Total de IPs a bloquear: {len(ips_data)}
# ============================================================

# Instrucciones de uso:
# 1. Guardar como blocklist.sh
# 2. chmod +x blocklist.sh
# 3. sudo ./blocklist.sh
# 4. O agregar a /etc/iptables/rules.v4 o /etc/iptables/rules.v6

BLOCKCHAIN="blocklist-sniffer"

# Crear cadena si no existe
iptables -N $BLOCKCHAIN 2>/dev/null || iptables -F $BLOCKCHAIN
ip6tables -N $BLOCKCHAIN 2>/dev/null || ip6tables -F $BLOCKCHAIN

# Limpiar reglas anteriores
iptables -F $BLOCKCHAIN
ip6tables -F $BLOCKCHAIN

# Redirigir tráfico bloqueado (opcional, retorna conex拒绝)
# iptables -A $BLOCKCHAIN -j RETURN
# ip6tables -A $BLOCKCHAIN -j RETURN

"""

        blocked_count = 0
        for ip, result in ips_data.items():
            if result["risk_level"] in ["suspicious", "dangerous"]:
                blocked_count += 1
                comment = f"# {result['risk_emoji']} {result['risk_level']}: {result.get('description', '')}"
                content += f"{comment}\n"

                if ":" in ip:
                    content += f"ip6tables -A $BLOCKCHAIN -s {ip} -j DROP\n"
                else:
                    content += f"iptables -A $BLOCKCHAIN -s {ip} -j DROP\n"

        content += f"""

# Aplicar a INPUT y FORWARD (descomentar para activar)
# iptables -I INPUT -j $BLOCKCHAIN
# iptables -I FORWARD -j $BLOCKCHAIN

echo "Blocklist aplicada: {blocked_count} IPs bloqueadas"
"""

        with open(output_file, "w") as f:
            f.write(content)

        return blocked_count

    def generate_unbound_conf(self, ips_data, output_file):
        content = f"""# ============================================================
# Blocklist para Unbound DNS
# Generada por Network Sniffer
# Fecha: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
# Total de IPs bloqueadas: {len(ips_data)}
# ============================================================

# Instrucciones de uso:
# 1. Copiar a /etc/unbound/unbound.conf.d/blocklist.conf
# 2. Reiniciar unbound: sudo systemctl restart unbound

"""

        blocked_count = 0
        for ip, result in ips_data.items():
            if result["risk_level"] in ["suspicious", "dangerous"]:
                blocked_count += 1
                comment = f"# {result['risk_emoji']} {result['risk_level']}: {result.get('description', '')}"
                content += f"{comment}\n"
                content += f'local-zone: "{ip}." static\n'
                content += f'local-data: "{ip}. A 127.0.0.1"\n\n'

        with open(output_file, "w") as f:
            f.write(content)

        return blocked_count

    def generate_hosts_file(self, ips_data, output_file):
        content = f"""# ============================================================
# Blocklist en formato hosts
# Generada por Network Sniffer
# Fecha: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
# Total de IPs bloqueadas: {len(ips_data)}
# ============================================================

# Instrucciones de uso:
# 1. Copiar a /etc/hosts (Linux) o usar con bloqueador de anuncios
# 2. O usar con AdGuard Home, Pi-hole, etc.

127.0.0.1 localhost
::1 localhost ip6-localhost ip6-loopback

"""

        blocked_count = 0
        for ip, result in ips_data.items():
            if result["risk_level"] in ["suspicious", "dangerous"]:
                blocked_count += 1
                comment = f"# {result['risk_emoji']} {result['risk_level']}: {result.get('description', '')}"
                content += f"{comment}\n"
                content += f"127.0.0.1 {ip}\n"
                content += f"::1 {ip}\n\n"

        with open(output_file, "w") as f:
            f.write(content)

        return blocked_count

    def generate_csv_report(self, ips_data, output_file):
        content = "ip,risk_level,risk_score,risk_emoji,description,country,asn,domain\n"

        for ip, result in ips_data.items():
            if result["risk_level"] in ["suspicious", "dangerous"]:
                geo = result.get("geo_info", {})
                country = geo.get("country", "")
                asn = geo.get("asn", "")
                domain = result.get("domain", "")

                description = result.get("description", "").replace('"', '""')

                content += f'{ip},{result["risk_level"]},{result["risk_score"]},{result["risk_emoji"]},"{description}",{country},{asn},{domain}\n'

        with open(output_file, "w") as f:
            f.write(content)

        return sum(
            1
            for ip, r in ips_data.items()
            if r["risk_level"] in ["suspicious", "dangerous"]
        )

    def generate_all_blocklists(self, logs_dir, formats=None, risk_threshold=50):
        if formats is None:
            formats = [
                "mikrotik",
                "dnsmasq",
                "iptables",
                "hosts",
                "bind",
                "unbound",
                "csv",
            ]

        print("\n" + "=" * 60)
        print(f"GENERANDO BLOCKLISTS (riesgo >= {risk_threshold})")
        print("=" * 60)

        data = self.load_logs(logs_dir)
        ips_data_full = self.get_all_ips_with_risk(data)

        # Filtrar por threshold
        ips_data = {
            ip: data
            for ip, data in ips_data_full.items()
            if data.get("risk_score", 0) >= risk_threshold
        }

        print(f"  IPs con riesgo >= {risk_threshold}: {len(ips_data)}")

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        results = {}

        if "mikrotik" in formats:
            output_file = os.path.join(
                self.output_dir, f"mikrotik_blocklist_{timestamp}.rsc"
            )
            count = self.generate_mikrotik_script(ips_data, output_file)
            results["mikrotik"] = {"file": output_file, "count": count}
            print(f"  ✓ MikroTik: {count} IPs -> {output_file}")

        if "dnsmasq" in formats:
            output_file = os.path.join(
                self.output_dir, f"dnsmasq_blocklist_{timestamp}.conf"
            )
            count = self.generate_dnsmasq_conf(ips_data, output_file)
            results["dnsmasq"] = {"file": output_file, "count": count}
            print(f"  ✓ DNSMasq: {count} IPs -> {output_file}")

        if "iptables" in formats:
            output_file = os.path.join(
                self.output_dir, f"iptables_blocklist_{timestamp}.sh"
            )
            count = self.generate_iptables_script(ips_data, output_file)
            results["iptables"] = {"file": output_file, "count": count}
            print(f"  ✓ iptables: {count} IPs -> {output_file}")

        if "hosts" in formats:
            output_file = os.path.join(self.output_dir, f"hosts_blocklist_{timestamp}")
            count = self.generate_hosts_file(ips_data, output_file)
            results["hosts"] = {"file": output_file, "count": count}
            print(f"  ✓ Hosts: {count} IPs -> {output_file}")

        if "bind" in formats:
            output_file = os.path.join(
                self.output_dir, f"bind_zone_blocklist_{timestamp}.zone"
            )
            count = self.generate_bind_zone_file(ips_data, output_file)
            results["bind"] = {"file": output_file, "count": count}
            print(f"  ✓ BIND: {count} IPs -> {output_file}")

        if "unbound" in formats:
            output_file = os.path.join(
                self.output_dir, f"unbound_blocklist_{timestamp}.conf"
            )
            count = self.generate_unbound_conf(ips_data, output_file)
            results["unbound"] = {"file": output_file, "count": count}
            print(f"  ✓ Unbound: {count} IPs -> {output_file}")

        if "csv" in formats:
            output_file = os.path.join(self.output_dir, f"blocklist_{timestamp}.csv")
            count = self.generate_csv_report(ips_data, output_file)
            results["csv"] = {"file": output_file, "count": count}
            print(f"  ✓ CSV: {count} IPs -> {output_file}")

        print("=" * 60)

        return results


def generate_blocklists(
    logs_dir, output_dir="blocklists", formats=None, risk_threshold=50
):
    generator = BlocklistGenerator(output_dir)
    return generator.generate_all_blocklists(logs_dir, formats, risk_threshold)
