"""
CLI de camaudit.

Ejemplos:
    python -m camaudit.cli scan --network 192.168.1.0/24 --dry-run
    python -m camaudit.cli scan --network 192.168.1.0/24 --i-have-authorization --output reporte.json
"""

import argparse
import sys
from datetime import datetime, timezone
 
from colorama import Fore, Style, init as colorama_init
 
from .discovery import (
    scan_network,
    onvif_discover,
    confirmed_ips_from_onvif,
    DEFAULT_CAMERA_PORTS,
)
from .checkers import check_device
from .report import build_report, save_report
 
colorama_init()
 
LEGAL_BANNER = f"""{Fore.YELLOW}
camaudit — auditoría de credenciales por defecto en cámaras IP
Usá esta herramienta SOLO en redes propias o con autorización explícita
y por escrito del titular. El uso no autorizado puede ser delito.
{Style.RESET_ALL}"""
 
 
def cmd_scan(args):
    print(LEGAL_BANNER)
 
    if not args.dry_run and not args.i_have_authorization:
        print(
            f"{Fore.RED}Falta confirmar autorización. Volvé a ejecutar con "
            f"--i-have-authorization si tenés permiso para auditar "
            f"{args.network}, o usá --dry-run para simular.{Style.RESET_ALL}"
        )
        sys.exit(1)
 
    if args.dry_run:
        print(f"[DRY-RUN] Escanearía la red {args.network} en puertos "
              f"{args.ports or DEFAULT_CAMERA_PORTS}, y haría descubrimiento "
              f"ONVIF para confirmar cuáles son cámaras reales. No se envía "
              f"tráfico real.")
        return
 
    print(
        f"[{datetime.now(timezone.utc).isoformat()}] Iniciando auditoría "
        f"autorizada sobre {args.network}\n"
    )
 
    # Descubrimiento ONVIF primero: nos da el set de IPs que hablan un
    # protocolo exclusivo de cámaras/NVRs, para poder confiar en el
    # resultado más adelante.
    onvif_responses = onvif_discover(timeout=args.timeout)
    confirmed_ips = confirmed_ips_from_onvif(onvif_responses)
    print(f"Dispositivos confirmados como cámara por ONVIF: {len(confirmed_ips)}")
 
    devices = scan_network(
        args.network,
        ports=args.ports,
        timeout=args.timeout,
        threads=args.threads,
    )
    print(f"Dispositivos con puertos abiertos encontrados: {len(devices)}\n")
 
    findings = []
    for dev in devices:
        result = check_device(
            dev["ip"], dev["port"], confirmed_ips, timeout=args.timeout
        )
        if result:
            findings.append(result)
            tag = (
                f"{Fore.RED}[CÁMARA CONFIRMADA VULNERABLE]{Style.RESET_ALL}"
                if result["confidence"] == "confirmed"
                else f"{Fore.YELLOW}[DISPOSITIVO SIN CONFIRMAR, VULNERABLE]{Style.RESET_ALL}"
            )
            print(
                f"{tag} {dev['ip']}:{dev['port']} -> "
                f"{result['user']}:{result['password']}"
            )
 
    report = build_report(args.network, findings)
 
    if args.output:
        save_report(report, args.output)
        print(f"\nReporte guardado en {args.output}")
 
    n_confirmed = len(report["camaras_confirmadas_vulnerables"])
    n_unconfirmed = len(report["otros_dispositivos_vulnerables"])
    print(
        f"\nResumen: {n_confirmed} cámara(s) confirmada(s) vulnerable(s), "
        f"{n_unconfirmed} otro(s) dispositivo(s) sin confirmar con "
        f"credenciales por defecto, de {len(devices)} puerto(s) abiertos "
        f"revisados."
    )
 
 
def parse_ports(value):
    if not value:
        return None
    return [int(p) for p in value.split(",")]
 
 
def main():
    parser = argparse.ArgumentParser(prog="camaudit")
    sub = parser.add_subparsers(dest="command", required=True)
 
    scan_parser = sub.add_parser("scan", help="Escanea una red buscando cámaras con credenciales por defecto")
    scan_parser.add_argument("--network", required=True, help="Rango CIDR, ej. 192.168.1.0/24")
    scan_parser.add_argument("--ports", type=parse_ports, default=None, help="Puertos separados por coma")
    scan_parser.add_argument("--timeout", type=float, default=2.0)
    scan_parser.add_argument("--threads", type=int, default=50)
    scan_parser.add_argument("--output", default=None, help="Archivo de salida .json o .csv")
    scan_parser.add_argument("--i-have-authorization", action="store_true", dest="i_have_authorization")
    scan_parser.add_argument("--dry-run", action="store_true")
    scan_parser.set_defaults(func=cmd_scan)
 
    args = parser.parse_args()
    args.func(args)
 
 
if __name__ == "__main__":
    main()