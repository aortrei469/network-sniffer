# Network Sniffer - Documentación Técnica Completa

## 1. Resumen del Proyecto

**Network Sniffer** es una herramienta de código abierto para Linux (específicamente diseñada para Ubuntu) que permite:

1. **Capturar y analizar** todas las conexiones de red entrantes y salientes de una máquina
2. **Monitorear consultas DNS** - dominios consultados, tipos de query, IPs resueltas
3. **Clasificar conexiones** por nivel de peligrosidad usando bases de datos offline
4. **Generar informes** en múltiples formatos (TXT, JSON, HTML)
5. **Exportar blocklists** para integrar con DNS servers (dnsmasq, BIND, Unbound) y firewalls (iptables, MikroTik)

---

## 2. Arquitectura del Sistema

```
+-----------------------------------------------------------------------------+
|                         NETWORK SNIFFER v1.0                                |
+-----------------------------------------------------------------------------+
|                                                                             |
|  +--------------+    +--------------+    +--------------+                 |
|  | DNS Capture  |    | Packet       |    | TLS/HTTP     |                 |
|  | (tcpdump)    |    | Capture      |    | Analyzer     |                 |
|  |              |    | (scapy)      |    |              |                 |
|  +------+-------+    +------+-------+    +------+-------+                 |
|         |                    |                    |                      |
|         +--------------------+--------------------+                      |
|                              v                                            |
|                    +---------------+                                       |
|                    |   JSON Logs   |                                       |
|                    +-------+-------+                                       |
|                            |                                              |
|         +------------------+------------------+                          |
|         v                  v                  v                          |
|  +-------------+   +-------------+   +-------------+                     |
|  | GeoIP       |   | Threat      |   | IP          |                     |
|  | Lookup      |   | Analysis    |   | Enrichment  |                     |
|  | (offline)   |   | (offline)   |   | (PTR+WHOIS) |                     |
|  +-------------+   +-------------+   +-------------+                     |
|         |                  |                  |                          |
|         +------------------+------------------+                          |
|                              v                                            |
|                    +---------------+                                      |
|                    |   OUTPUT      |                                      |
|                    |  - TXT        |                                      |
|                    |  - JSON       |                                      |
|                    |  - HTML       |                                      |
|                    |  - Blocklists |                                      |
|                    +---------------+                                      |
+-----------------------------------------------------------------------------+
```

**Componentes principales:**

| Módulo | Descripción |
|--------|-------------|
| `dns_capture.py` | Captura DNS con tcpdump |
| `packet_capture.py` | Captura paquetes con scapy |
| `geoip.py` | Lookup geográfico offline |
| `threat_lookup.py` | Análisis de amenazas (Spamhaus) |
| `ip_enrichment.py` | Enrichment (PTR, WHOIS, Tor, etc.) |
| `report.py` | Generación de informes y blocklists |

---

## 3. Fases del Proyecto

### Fase 1: Captura de Tráfico DNS

**Objetivo**: Monitorear todas las consultas DNS realizadas por el sistema

**Tecnología**: `tcpdump` - analizador de paquetes de línea de comandos

**Funcionamiento**:
- Se ejecuta `tcpdump` en modo listening en el puerto 53 (DNS)
- Captura tanto tráfico UDP como TCP
- Parsea las consultas para extraer:
  - Dominio consultado
  - Tipo de query (A, AAAA, MX, CNAME, etc.)
  - IP de origen y destino
  - ID de transacción para correlacionar con respuestas

**Datos almacenados** (`dns_queries.json`):
```json
{
  "queries": [
    {
      "timestamp": "2026-03-14T12:00:00",
      "domain": "ejemplo.com",
      "type": "A",
      "src_ip": "192.168.1.100",
      "dst_ip": "8.8.8.8"
    }
  ],
  "responses": [...]
}
```

---

### Fase 2: Captura de Paquetes de Red

**Objetivo**: Analizar todas las conexiones TCP/UDP salientes y entrantes

**Tecnología**: `Scapy` - biblioteca Python para manipulación de paquetes

**Funcionamiento**:
- Sniffing de paquetes en la interfaz de red
- Extracción de metadatos de cada conexión:
  - IP origen y destino
  - Puerto origen y destino
  - Protocolo (TCP, UDP, ICMP)
  - Flags TCP (SYN, ACK, FIN, etc.)
- Análisis de capas superiores:
  - **HTTP**: Extracción de URLs de peticiones GET/POST
  - **TLS/SSL**: Extracción de Server Name Indication (SNI)

**Datos almacenados** (`connections.json`):
```json
{
  "connections": [
    {
      "timestamp": "2026-03-14T12:00:01",
      "src_ip": "192.168.1.100",
      "dst_ip": "93.184.216.34",
      "direction": "outbound",
      "protocol": "TCP",
      "info": {
        "dst_port": 443,
        "port_name": "HTTPS",
        "sni": "www.ejemplo.com"
      }
    }
  ],
  "stats": {
    "93.184.216.34": {
      "count": 15,
      "ports": {"443": 15, "80": 3},
      "protocols": {"TCP"},
      "first_seen": "2026-03-14T12:00:01",
      "last_seen": "2026-03-14T12:15:00"
    }
  }
}
```

---

### Fase 3: Análisis de Geolocalización (Offline)

**Objetivo**: Determinar la ubicación geográfica y ASN de cada IP

**Tecnología**: MaxMind GeoLite2 - Base de datos offline de geolocalización

**Funcionamiento**:
- Carga de archivo BIN de MaxMind en memoria
- Lookup offline (sin consultas a APIs externas)
- Extracción de:
  - Código de país (ISO 3166-1)
  - Nombre del país
  - Número de Sistema Autónomo (ASN)
  - Organización (ISP/Hosting)

**Lista de rangos IP privados** (excluidos del análisis):
- 10.0.0.0/8
- 172.16.0.0/12
- 192.168.0.0/16
- 127.0.0.0/8
- 169.254.0.0/16 (Link-local)
- 100.64.0.0/10 (Shared Address Space)

---

### Fase 4: Análisis de Amenazas (Offline)

**Objetivo**: Clasificar cada IP por nivel de peligrosidad

**Tecnologías**: Listas de amenazas offline

**Fuentes de datos**:
1. **Spamhaus DROP/EDROP**
   - IPs de spam known
   - Redes de malware
   - Botnets
   - ~1500+ rangos IP

2. **ThreatFox IOC** (Abuse.ch) - *requiere autenticación*
   - IPs conocidas por malware
   - Command & Control (C2)

3. **Lista blanca hardcodeada**
   - Servicios conocidos (Google, AWS, Microsoft, GitHub, etc.)
   - ~150 dominios populares

**Fuentes adicionales (Modo Deep)**:
4. **Tor Exit Nodes**
   - Lista de nodos de salida Tor

5. **Emerging Threats**
   - IPs comprometidas conocidas

6. **DShield**
   - IPs reportadas por abuso

**Clasificación de Peligrosidad**:

| Nivel | Emoji | Score | Criterios |
|-------|-------|-------|-----------|
| Seguro | 🟢 | 0 | IP privada o en lista blanca |
| Desconocido | 🟡 | 25 | IP pública no encontrada en ninguna lista |
| Sospechoso | 🟠 | 50 | IP de país con restricciones (KP, IR, SY) |
| Peligroso | 🔴 | 100 | IP en listas de malware/spam/Tor |

**Modo Deep añade:**
- Resolución PTR (DNS inversa)
- Información WHOIS (AS, organización, país de registro)
- Identificación de Cloud/Hosting (AWS, Google, Azure, etc.)
- Detección de países de riesgo (CN, RU, IR, etc.)

---

### Fase 4b: Enriquecimiento de IPs (Modo Deep)

**Objetivo**: Obtener información adicional sobre IPs desconocidas

**Tecnologías**:
- Resolución DNS inversa (PTR)
- Comandos WHOIS
- Listas adicionales de amenazas

**Información obtenida**:
1. **Registro PTR**: Nombre de host asociado a la IP
2. **Información WHOIS**:
   - Organización (AS)
   - Número AS (ASN)
   - País de registro
   - Contacto de abuso
3. **Detección de servicios**:
   - Cloud/Hosting (AWS, Google, Azure, etc.)
   - Proveedores de VPN
   - Nodos Tor

---

### Fase 5: Generación de Informes

**Objetivo**: Presentar los resultados de forma estructurada

**Formatos de salida**:

1. **TXT** - Informe legible por humanos
   - Resumen de consultas DNS
   - Estadísticas de conexiones
   - Análisis de amenazas
   - Recomendaciones

2. **JSON** - Datos estructurados
   - Completo para procesamiento automatizado
   - Incluye todos los metadatos

3. **HTML** - Dashboard visual
   - Tablas ordenables
   - Gráficos de distribución
   - Diseño responsive

---

### Fase 6: Generación de Blocklists

**Objetivo**: Exportar IPs peligrosas para integración con sistemas de seguridad

**Formatos soportados**:

| Formato | Destino | Descripción |
|---------|---------|-------------|
| MikroTik | RouterOS | Script .rsc para import |
| DNSMasq | DNS Server | Directivas `address=/ip/127.0.0.1` |
| iptables | Firewall | Script bash con reglas DROP |
| BIND | DNS Server | Zona DNS con registros A |
| Unbound | DNS Resolver | Configuración local-zone |
| Hosts | /etc/hosts | Formato estándar |
| CSV | Excel/BD | Para procesamiento |

**Umbral de riesgo**:

Por defecto, solo se incluyen IPs con riesgo >= 50 en las blocklists.
Puedes ajustar el threshold:

| Threshold | Descripción |
|-----------|-------------|
| 25 | Todas las IPs desconocidas (mayor falsos positivos) |
| 50 | Solo sospechosas/peligrosas (recomendado) |
| 75 | Solo muy sospechosas |
| 100 | Solo confirmadas como peligrosas |

**Blocklist automática**:

Puedes generar blocklists automáticamente tras el análisis:

```bash
# Analisis + blocklist en un solo comando
python3 sniffer.py --analyze -I logs/ -B

# Con analisis profundo
python3 sniffer.py --analyze -I logs/ -m deep -B
```

---

## 4. Tecnologías y Herramientas

### Dependencias de Python

| Paquete | Versión | Uso |
|---------|---------|-----|
| scapy | >=2.5.0 | Captura y análisis de paquetes |
| maxminddb | >=1.10.0 | Lookup geográfico offline |
| colorama | >=0.4.6 | Colores en terminal |
| requests | >=2.28.0 | Descarga de bases de datos |

### Herramientas del Sistema

| Herramienta | Paquete | Uso |
|------------|---------|-----|
| tcpdump | tcpdump | Captura de paquetes DNS |
| whois | whois | Información de IPs |
| dig | dnsutils | Consultas DNS manuales |
| ip | iproute2 | Información de interfaces |

---

## 5. Estructura de Archivos

```
network_sniffer/
├── sniffer.py                    # Entry point principal
├── requirements.txt               # Dependencias Python
├── README.md                     # Este archivo
│
├── modules/
│   ├── __init__.py
│   ├── config.py                 # Configuración centralizada
│   │   ├── Rutas de archivos
│   │   ├── URLs de descarga
│   │   ├── Lista blanca de dominios
│   │   ├── Rangos IP privados
│   │   ├── Nombres de puertos comunes
│   │   └── Niveles de riesgo
│   │
│   ├── dns_capture.py            # Captura DNS con tcpdump
│   │   ├── Clase DNSCapture
│   │   │   ├── _parse_dns_query()
│   │   │   ├── _parse_dns_response()
│   │   │   ├── start()/stop()
│   │   │   └── get_data()
│   │   ├── clear_dns_cache()     # Limpia caché systemd-resolved
│   │   └── get_network_interfaces()
│   │
│   ├── packet_capture.py         # Captura de paquetes con scapy
│   │   ├── Clase PacketCapture
│   │   │   ├── _process_packet()
│   │   │   ├── _extract_http_url()
│   │   │   ├── _extract_tls_sni()
│   │   │   ├── start()/stop()
│   │   │   └── get_connection_stats()
│   │   └── Detección de puertos sospechosos
│   │
│   ├── geoip.py                  # Lookup geográfico offline
│   │   ├── Clase GeoIPLookup
│   │   │   ├── lookup()
│   │   │   ├── lookup_batch()
│   │   │   ├── is_private_ip()
│   │   │   └── is_whitelisted_range()
│   │   └── Mapeo de códigos de país
│   │
│   ├── threat_lookup.py          # Análisis de amenazas
│   │   ├── Clase ThreatLookup
│   │   │   ├── check_ip()
│   │   │   ├── check_connection()
│   │   │   ├── check_batch()
│   │   │   └── get_risk_summary()
│   │   ├── Carga de ThreatFox
│   │   └── Carga de Spamhaus
│   │
│   ├── report.py                 # Generación de informes
│   │   ├── Clase ReportGenerator
│   │   │   ├── generate_dns_report()
│   │   │   ├── generate_connections_report()
│   │   │   ├── generate_threat_analysis()
│   │   │   └── generate_html_report()
│   │   └── Clase BlocklistGenerator
│   │       ├── generate_mikrotik_script()
│   │       ├── generate_dnsmasq_conf()
│   │       ├── generate_iptables_script()
│   │       └── generate_hosts_file()
│   │
│   └── update_db.py              # Actualizador de bases de datos
│       ├── download_threatfox()
│       ├── download_spamhaus()
│       └── download_geolite2()
│
├── logs/                         # Directorio de logs
│   ├── dns_queries.json
│   ├── connections.json
│   ├── tls_sni.json
│   └── informes/
│       ├── informe_20260314_120000.txt
│       ├── informe_20260314_120000.json
│       └── informe_20260314_120000.html
│
├── databases/                    # Bases de datos offline
│   ├── GeoLite2-Country.mmdb
│   ├── threatfox_ips.txt
│   └── spamhaus_drop.txt
│
└── blocklists/                   # Blocklists generadas
    ├── mikrotik_blocklist_*.rsc
    ├── dnsmasq_blocklist_*.conf
    ├── iptables_blocklist_*.sh
    └── hosts_blocklist_
```

---

## 6. Uso del Sistema

### Instalación

```bash
# Clonar o copiar el proyecto
cd network_sniffer

# Instalar dependencias Python
pip install -r requirements.txt

# Instalar herramientas del sistema
sudo apt install tcpdump whois dnsutils

# Actualizar bases de datos (opcional pero recomendado)
python3 sniffer.py --update-db
```

### Flujo de Trabajo Completo

```bash
# 1. Limpiar caché DNS del sistema
sudo resolvectl flush-caches

# 2. Iniciar captura (como root, necesarios privilegios)
sudo python3 sniffer.py --capture

# 3. Usar el equipo normalmente (navegar, ejecutar apps, etc.)

# 4. Detener captura con Ctrl+C

# 5. Generar informe de análisis (elegir modo)
python3 sniffer.py --analyze -I logs/           # Modo rápido
python3 sniffer.py --analyze -I logs/ -m deep   # Modo profundo

# 6. Generar blocklists
python3 sniffer.py --blocklist -I logs/
```

### Modos de Análisis

El sistema ofrece dos modos de análisis:

#### Modo Rápido (`fast`)
- Verifica listas de amenazas offline (Spamhaus DROP/EDROP)
- **Tiempo**: Segundos
- **Ideal para**: Análisis inicial rápido

```bash
python3 sniffer.py --analyze -I logs/
python3 sniffer.py --analyze -I logs/ -m fast
```

#### Modo Profundo (`deep`)
- Resolución DNS inversa (PTR)
- Consultas WHOIS para obtener organización, AS, país
- Verifica listas adicionales (Tor Exit Nodes, Emerging Threats, DShield)
- Caché WHOIS para evitar consultas repetidas
- **Tiempo**: 1-3 minutos (dependiendo del número de IPs)
- **Ideal para**: Análisis completo para restricciones de seguridad

```bash
python3 sniffer.py --analyze -I logs/ -m deep
```

**¿Qué información proporciona el modo profundo?**
```
76.223.54.146:
  PTR: a904c694c05102f30.awsglobalaccelerator.com
  Org: Amazon.com, Inc. (AMAZO-4)
  Pais: US
  ! Cloud/Hosting: Amazon.com, Inc.

120.243.32.102:
  Org: China Mobile Communications Corporation
  Pais: CN
  ASN: 9808
  ! Pais de riesgo: CN
```

### Opciones de Línea de Comandos

```bash
# Modo captura
sudo python3 sniffer.py --capture                    # Captura en todas las interfaces
sudo python3 sniffer.py --capture -i wlan0         # Interfaz específica
sudo python3 sniffer.py --capture -o /tmp/logs     # Directorio personalizado
sudo python3 sniffer.py --capture --duration 300    # Duración limitada (5 min)

# Modo análisis - Rapido
python3 sniffer.py --analyze -I logs/               # Analizar logs
python3 sniffer.py --analyze -I logs/ -o informes/  # Directorio de informes

# Modo análisis - Profundo
python3 sniffer.py --analyze -I logs/ -m deep       # Analisis completo

# Analisis + Blocklist automatica
python3 sniffer.py --analyze -I logs/ -B            # Analisis + blocklist (riesgo >= 50)
python3 sniffer.py --analyze -I logs/ -B -r 25      # Blocklist con threshold 25
python3 sniffer.py --analyze -I logs/ -B -r 75      # Blocklist solo muy peligrosas
python3 sniffer.py --analyze -I logs/ -m deep -B    # Analisis profundo + blocklist

# Blocklists (solo)
python3 sniffer.py --blocklist -I logs/              # Generar todas las blocklists
python3 sniffer.py --blocklist -I logs/ --format mikrotik dnsmasq
python3 sniffer.py --blocklist -I logs/ -r 25       # Con threshold personalizado

# Actualizar bases de datos
python3 sniffer.py --update-db
```

### Comparativa de Modos

| Caracteristica | Modo Fast | Modo Deep |
|----------------|------------|-----------|
| Listas de amenazas (Spamhaus) | ✅ | ✅ |
| Resolucion PTR | ❌ | ✅ |
| Consultas WHOIS | ❌ | ✅ |
| Listas Tor/Emerging/DShield | ❌ | ✅ |
| Cache WHOIS | ❌ | ✅ |
| Blocklist automatica | ✅ | ✅ |
| Tiempo (150 IPs) | ~5 seg | ~2 min |
| Uso recomendado | Exploracion rapida | Restricciones/seguridad |

---

## 7. Formato de los Datos

### dns_queries.json

```json
{
  "queries": [
    {
      "timestamp": "2026-03-14T10:30:15.123456",
      "domain": "www.google.com",
      "type": "A",
      "src_ip": "192.168.1.100",
      "src_port": "54321",
      "dst_ip": "8.8.8.8",
      "dst_port": "53",
      "transaction_id": "12345"
    }
  ],
  "responses": [
    {
      "timestamp": "2026-03-14T10:30:15.234567",
      "response_to_transaction": "12345",
      "query_type": "A",
      "answers": ["142.250.185.46"],
      "src_ip": "8.8.8.8",
      "dst_ip": "192.168.1.100"
    }
  ],
  "captured_at": "2026-03-14T10:30:15"
}
```

### connections.json

```json
{
  "connections": [
    {
      "timestamp": "2026-03-14T10:30:16.345678",
      "src_ip": "192.168.1.100",
      "dst_ip": "142.250.185.46",
      "direction": "outbound",
      "protocol": "TCP",
      "info": {
        "src_port": 443,
        "dst_port": 443,
        "flags": "PA",
        "port_name": "HTTPS",
        "sni": "www.google.com"
      },
      "sni": "www.google.com"
    }
  ],
  "stats": {
    "142.250.185.46": {
      "count": 15,
      "ports": {"443": 14, "80": 1},
      "protocols": ["TCP"],
      "first_seen": "2026-03-14T10:30:16",
      "last_seen": "2026-03-14T10:45:30"
    }
  },
  "captured_at": "2026-03-14T10:45:30"
}
```

---

## 8. Detección de Amenazas

### Puertos Sospechosos

| Puerto | Nombre | Riesgo |
|--------|--------|--------|
| 4444 | Metasploit | Default meterpreter port |
| 5555 | Android ADB | Posible compromiso |
| 31337 | Back Orifice | Troyano conocido |
| 12345 | NetBus | Troyano conocido |
| 27374 | SubSeven | Troyano conocido |
| 6667 | IRC | Posible bot |

### Países de Alto Riesgo

- **KP** - North Korea
- **IR** - Iran
- **SY** - Syria
- **CU** - Cuba
- **VE** - Venezuela

---

## 9. Integración con Sistemas Externos

### MikroTik RouterOS

```bash
# Importar blocklist
/campos/mikrotik_blocklist_20260314.rsc

# Ver lista
/ip firewall address-list print where list=blocklist-sniffer

# Aplicar regla de bloqueo
/ip firewall filter add chain=forward src-address-list=blocklist-sniffer action=drop
```

### DNSMasq

```bash
# Copiar configuración
sudo cp dnsmasq_blocklist_*.conf /etc/dnsmasq.d/blocklist.conf

# Reiniciar
sudo systemctl restart dnsmasq
```

### iptables

```bash
# Aplicar blocklist
sudo ./iptables_blocklist_*.sh

# Ver reglas
sudo iptables -L blocklist-sniffer -n
```

---

## 10. Limitaciones y Consideraciones

### Limitaciones Técnicas

1. **Captura local**: Solo captura tráfico de la máquina donde se ejecuta (no es un sniffer de red completo)

2. **Puertos privilegiados**: Requiere root para capturar paquetes

3. **Bases de datos offline**: Menor cobertura que APIs online (ThreatFox requiere autenticación)

4. **TLS/HTTPS**: Limitaciones en el contenido cifrado:
   
   **Lo que SÍ se captura:**
   - Consultas DNS (texto plano, puerto 53)
   - Direcciones IP de origen y destino
   - Puertos de origen y destino
   - SNI (Server Name Indication) - nombre del dominio en handshake TLS
   - metadatos de conexiones (timing, duración, volumen)
   
   **Lo que NO se captura:**
   - URLs HTTPS completas (cifradas)
   - Contenido de peticiones/respuestas HTTP
   - Cookies, tokens de sesión
   - Datos de formularios
   - Cuerpo de emails, mensajes, etc.

   **Nota sobre TLS 1.3**: El cifrado del contenido afecta igual a TLS 1.2 y 1.3. EI sniffer puede ver DNS y SNI (ambos en texto plano), pero no el contenido cifrado. TLS 1.3 no reduce la visibilidad de metadatos comparado con versiones anteriores.

5. **VPN/Tunnel**: El tráfico dentro de VPNs puede no ser visible (depende de la configuración)

6. **IPv6**: Soporte parcial para direcciones IPv6

### Lo que puedes analizar con los datos capturados

Incluso con el contenido cifrado, puedes identificar:

- **A qué dominios te conectas** (via DNS + SNI)
- **A qué IPs te conectas** (todas las conexiones)
- **Qué puertos/protocolos usas** (HTTP, HTTPS, SSH, etc.)
- **Cuánto tráfico generas** a cada destino
- **Patrones de comportamiento** (horarios, frecuencia)
- **Conexiones sospechosas** (IPs maliciosas, países de riesgo)

### Consideraciones de Privacidad

1. **Datos en logs**: Los logs contienen:
   - Dominios consultados (DNS y SNI)
   - Direcciones IP
   - Puertos y protocolos
   - **NO contienen** contenido de páginas, contraseñas, cookies, etc.

2. **Almacenamiento**: Los logs deben protegerse adecuadamente (contienen metadatos de navegación)

3. **Conexiones VPN**: El tráfico VPN puede no ser visible

4. **IPv6**: Soporte parcial para direcciones IPv6

### Recomendaciones

1. Actualizar bases de datos periódicamente
2. Revisar informes regularmente
3. Exportar blocklists a sistemas de seguridad
4. Usar en conjunto con otras herramientas de seguridad

---

## 11. Troubleshooting

### Error: "tcpdump: no se puede utlizar el dispositivo"

```bash
# Ver interfaces disponibles
ip link show

# Usar interfaz específica
sudo python3 sniffer.py --capture -i eth0
```

### Error: "Permission denied" al capturar

```bash
# El script debe ejecutarse con sudo
sudo python3 sniffer.py --capture
```

### Error: "maxminddb not available"

```bash
# Instalar biblioteca
pip install maxminddb

# O descargar base de datos GeoLite2
sudo apt install geoip-database
```

### Base de datos GeoIP vacía

```bash
# Actualizar bases de datos
sudo python3 sniffer.py --update-db
```

---

## 12. future Enhancements / Mejoras Futuras

- [ ] Soporte para captura de tráfico de red completa (no solo DNS)
- [ ] Integración con VirusTotal API
- [ ] Alertas en tiempo real
- [ ] Dashboard web interactivo
- [ ] Detección de protocolos cifrados
- [ ] Exportación a formato Suricata/Snort
- [ ] Soporte para Docker/containers
- [ ] Análisis de tráfico por aplicación

---

## 13. Licencia

Este proyecto es de uso libre para fines educativos y de seguridad personal.

---

## 14. Comparación con Otras Herramientas

### Herramientas Similares

| Herramienta | Tipo | Lo que hace | Diferencia con Network Sniffer |
|-------------|------|-------------|-------------------------------|
| **Wireshark** | Packet analyzer | Captura y analiza paquetes individuales | Análisis manual, no genera blocklists automáticas |
| **tcpdump** | Sniffer básico | Captura paquetes | Solo captura, no analiza amenazas |
| **ntopng** | Monitor bandwidth | Monitoriza uso de red por host | No detecta malware/IPs peligrosas |
| **Darkstat** | Estadisticas | Graficos de uso | No hace análisis de seguridad |
| **Zabbix/Nagios** | Monitorizacion | Alertas por umbrales | No analiza contenido de trafago |
| **NetHogs** | Por proceso | Ancho de banda por app | No detecta amenazas |

### Lo que hace unica a Network Sniffer

- **Analisis de amenazas offline** - Detecta IPs en listas de malware/spam
- **Enriquecimiento WHOIS** - Identifica organizaciones, paises
- **Blocklists automaticas** - Exporta directamente a MikroTik, iptables, dnsmasq
- **100% offline** - Sin dependencia de APIs externas
- **Orientada a seguridad** - No solo monitoriza, clasifica por riesgo

### Valoracion

| Aspecto | Nivel |
|---------|-------|
| Captura de trafago | Funcional, no tan completo como Wireshark |
| Analisis de amenazas | Unico en su categoria |
| Generacion de blocklists | No hay otra igual |
| Facilidad de uso | CLI simple |
| Documentacion | Completa |

### Conclusion

**Network Sniffer** es valiosa y unica para:
- Detectar conexiones sospechosas en tu maquina
- Generar blocklists para routers/firewalls
- Analisis offline sin enviar datos a servicios externos

**Para complementar**, combinar con:
- **Wireshark** - Analisis profundo de paquetes especificos
- **ntopng** - Monitorizacion de ancho de banda
- **Zabbix** - Monitorizacion enterprise

Para el caso de uso de "detectar conexiones peligrosas y generar restricciones" no hay otra herramienta open source que haga lo mismo de forma tan automatica y offline.

---

## 15. Referencias

- [Scapy Documentation](https://scapy.readthedocs.io/)
- [MaxMind GeoLite2](https://www.maxmind.com/)
- [ThreatFox by Abuse.ch](https://threatfox.abuse.ch/)
- [Spamhaus DROP](https://www.spamhaus.org/drop/)
- [tcpdump Manual](https://www.tcpdump.org/manpages/tcpdump.1.html)

---

**Version**: 1.1  
**Fecha**: Marzo 2026  
**Autor**: Arcadio Ortega Reinoso
