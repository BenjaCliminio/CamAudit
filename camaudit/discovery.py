"""
Descubrimiento de dispositivos: escaneo de puertos típicos de cámaras IP
y descubrimiento ONVIF (WS-Discovery) en la red local.
"""

import socket
import ipaddress
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
 
# Puertos comúnmente usados por cámaras IP / DVRs / NVRs
DEFAULT_CAMERA_PORTS = [80, 81, 8080, 8081, 554, 8000, 8899, 2020, 9000, 37777]
 
# Banners / cabeceras que ayudan a estimar la marca (solo informativo,
# no se usa para elegir credenciales ni para el nivel de confianza)
BRAND_HINTS = {
    "hikvision": ["hikvision", "dvrdvs", "app-webs"],
    "dahua": ["dahua", "dhipc"],
    "axis": ["axis"],
    "foscam": ["foscam"],
    "vivotek": ["vivotek"],
    "cp-plus": ["cp plus", "cp-plus"],
    "d-link": ["d-link", "dlink"],
}
 
 
def _scan_host_port(ip: str, port: int, timeout: float):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            if result != 0:
                return None
            banner = b""
            try:
                s.settimeout(timeout)
                banner = s.recv(256)
            except socket.timeout:
                pass
            return {"ip": ip, "port": port, "banner": banner.decode(errors="ignore")}
    except OSError:
        return None
 
 
def guess_brand(banner: str) -> str:
    banner_low = (banner or "").lower()
    for brand, hints in BRAND_HINTS.items():
        if any(h in banner_low for h in hints):
            return brand
    return "generic"
 
 
def scan_network(network: str, ports=None, timeout: float = 2.0, threads: int = 50):
    """
    Escanea un rango CIDR buscando puertos abiertos típicos de cámaras.
    Devuelve una lista de dicts: {ip, port, banner, brand}
    """
    ports = ports or DEFAULT_CAMERA_PORTS
    hosts = [str(h) for h in ipaddress.ip_network(network, strict=False).hosts()]
 
    found = []
    tasks = [(ip, port) for ip in hosts for port in ports]
 
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(_scan_host_port, ip, port, timeout): (ip, port)
            for ip, port in tasks
        }
        for future in as_completed(futures):
            res = future.result()
            if res:
                res["brand"] = guess_brand(res["banner"])
                found.append(res)
 
    return found
 
 
# ---------------------------------------------------------------------
# WS-Discovery (ONVIF) — probe multicast estándar para descubrir cámaras
# compatibles con ONVIF en la red local. A diferencia del escaneo de
# puertos, ONVIF es un protocolo que solo hablan cámaras/NVRs, así que
# una respuesta acá es una señal mucho más confiable que un puerto abierto.
# ---------------------------------------------------------------------
 
WSD_MULTICAST_ADDR = "239.255.255.250"
WSD_MULTICAST_PORT = 3702
 
WSD_PROBE_TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope"
            xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing"
            xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery"
            xmlns:dn="http://www.onvif.org/ver10/network/wsdl">
  <e:Header>
    <w:MessageID>uuid:{msg_id}</w:MessageID>
    <w:To e:mustUnderstand="true">urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>
    <w:Action a:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>
  </e:Header>
  <e:Body>
    <d:Probe>
      <d:Types>dn:NetworkVideoTransmitter</d:Types>
    </d:Probe>
  </e:Body>
</e:Envelope>"""
 
 
def onvif_discover(timeout: float = 3.0):
    """
    Envía un probe WS-Discovery por multicast y devuelve las respuestas
    crudas de los dispositivos: [{ip, raw}, ...]
    """
    msg_id = str(uuid.uuid4())
    probe = WSD_PROBE_TEMPLATE.format(msg_id=msg_id).encode("utf-8")
 
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    sock.settimeout(timeout)
 
    responses = []
    try:
        sock.sendto(probe, (WSD_MULTICAST_ADDR, WSD_MULTICAST_PORT))
        while True:
            try:
                data, addr = sock.recvfrom(65535)
                responses.append({"ip": addr[0], "raw": data.decode(errors="ignore")})
            except socket.timeout:
                break
    finally:
        sock.close()
 
    return responses
 
 
def confirmed_ips_from_onvif(onvif_responses: list) -> set:
    """
    Extrae el set de IPs que respondieron al probe ONVIF, para usarlas
    como señal de "esto es una cámara confirmada" en el resto del flujo.
    """
    return {r["ip"] for r in onvif_responses}