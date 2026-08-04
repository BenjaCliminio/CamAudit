"""
Verificadores de autenticación por protocolo.

Cada checker intenta autenticarse con una lista de credenciales por
defecto y reporta si alguna funcionó. No realizan ninguna acción más
allá de confirmar el login.
"""

import socket
import requests
from requests.auth import HTTPDigestAuth
 
from .creds import DEFAULT_CREDENTIALS
 
requests.packages.urllib3.disable_warnings()
 
 
def check_http(ip: str, port: int, confidence: str, timeout: float = 3.0):
    base_url = f"http://{ip}:{port}/"
 
    # Primero: ¿el sitio siquiera pide autenticación HTTP real (Basic/Digest)?
    # Si no devuelve 401 sin credenciales, es probable que use un login por
    # formulario HTML (routers, algunos DVRs) y cualquier GET devuelve 200
    # igual -> evaluarlo daría un falso positivo, así que se descarta.
    try:
        no_auth_resp = requests.get(base_url, timeout=timeout, verify=False)
    except requests.RequestException:
        return None
 
    if no_auth_resp.status_code != 401:
        return None
 
    for user, pwd in DEFAULT_CREDENTIALS:
        for auth_mode, auth_obj in (
            ("basic", (user, pwd)),
            ("digest", HTTPDigestAuth(user, pwd)),
        ):
            try:
                resp = requests.get(
                    base_url, auth=auth_obj, timeout=timeout, verify=False
                )
                if resp.status_code in (200, 201):
                    return {
                        "ip": ip,
                        "port": port,
                        "protocol": f"http-{auth_mode}",
                        "user": user,
                        "password": pwd,
                        "vulnerable": True,
                        "confidence": confidence,
                    }
            except requests.RequestException:
                continue
    return None
 
 
def check_rtsp(ip: str, port: int, confidence: str, timeout: float = 3.0):
    for user, pwd in DEFAULT_CREDENTIALS:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((ip, port))
                url = f"rtsp://{user}:{pwd}@{ip}:{port}/"
                request = (
                    f"DESCRIBE {url} RTSP/1.0\r\n"
                    f"CSeq: 1\r\n"
                    f"Accept: application/sdp\r\n\r\n"
                )
                s.sendall(request.encode())
                data = s.recv(1024).decode(errors="ignore")
                if "200 OK" in data:
                    return {
                        "ip": ip,
                        "port": port,
                        "protocol": "rtsp",
                        "user": user,
                        "password": pwd,
                        "vulnerable": True,
                        "confidence": confidence,
                    }
        except OSError:
            continue
    return None
 
 
def check_device(ip: str, port: int, confirmed_ips: set, timeout: float = 3.0):
    """
    confirmed_ips: set de IPs que respondieron al descubrimiento ONVIF
    (ver discovery.onvif_discover). Se usa solo para etiquetar el nivel
    de confianza del hallazgo, no cambia qué se prueba.
    """
    confidence = "confirmed" if ip in confirmed_ips else "unconfirmed"
 
    if port == 554:
        return check_rtsp(ip, port, confidence, timeout)
    return check_http(ip, port, confidence, timeout)