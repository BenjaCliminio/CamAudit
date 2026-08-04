# camaudit

Herramienta de auditoría de seguridad para detectar cámaras de vigilancia IP
(HTTP, RTSP, ONVIF) que siguen usando **credenciales por defecto** dentro de
una red autorizada.

El objetivo es dar a un auditor / equipo de seguridad interna una forma
rápida de encontrar cámaras mal configuradas antes de que lo haga un
atacante, y generar un reporte para que la compañía las corrija.

> ⚠️ **`camaudit` NO** transmite video, NO borra grabaciones, NO cambia
> configuraciones y NO deja backdoors. Solo intenta autenticarse con
> credenciales por defecto conocidas y reporta si funcionaron o no.
> Cualquier acción posterior a la detección es responsabilidad del auditor
> y debe estar dentro del alcance autorizado por escrito con el cliente.

---

## ⚖️ Aviso legal — leé esto antes de usar la herramienta

Usar `camaudit` contra redes o dispositivos que no sean tuyos, o sobre los
que no tengas **autorización explícita y por escrito** del dueño/administrador,
puede constituir un delito (acceso indebido a sistemas informáticos) en
Argentina (art. 153 bis del Código Penal) y en la gran mayoría de los países.

Por eso la herramienta:

- Requiere el flag `--i-have-authorization` para correr un scan real.
- Escribe en el log, en cada ejecución, la fecha, el rango escaneado y una
  advertencia de que el usuario declaró tener autorización.
- No hace nada por default: sin ese flag, solo simula (`--dry-run`).

Usalo exclusivamente en:
- Redes propias / de tu laboratorio.
- Redes de una compañía que te contrató para un pentest o auditoría, con
  alcance (scope) firmado.

## Instalación

```bash
git clone https://github.com/tu-usuario/camaudit.git
cd camaudit
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

## Uso básico

```bash
# Simulación (no envía nada, solo muestra qué haría)
python -m camaudit.cli scan --network 192.168.1.0/24 --dry-run

# Auditoría real, con autorización confirmada
python -m camaudit.cli scan --network 192.168.1.0/24 \
    --i-have-authorization \
    --output reporte.json
```

### Opciones principales

| Flag | Descripción |
|---|---|
| `--network` | Rango CIDR a escanear (ej. `192.168.1.0/24`) |
| `--ports` | Puertos a probar (por default: lista de puertos típicos de cámaras) |
| `--onvif` | Además del escaneo por puerto, hace descubrimiento ONVIF (WS-Discovery) en la red local |
| `--timeout` | Timeout por conexión en segundos (default 2) |
| `--threads` | Nivel de concurrencia (default 50) |
| `--output` | Archivo de salida (`.json` o `.csv`) |
| `--i-have-authorization` | Confirma que tenés autorización para auditar la red indicada |
| `--dry-run` | No realiza conexiones reales, solo muestra el plan de escaneo |

## Qué detecta

1. Descubrimiento: barre el rango de red buscando puertos abiertos
   típicos de cámaras IP (80, 8080, 8081, 554, 8000, 37777, 2020, 9000, etc.)
2. Fingerprint básico: intenta identificar marca/modelo por banner HTTP
   o respuesta RTSP (Hikvision, Dahua, Axis, Foscam, genéricas ONVIF, etc.)
3. Prueba de credenciales por defecto: contra los servicios detectados
   (HTTP Basic/Digest, RTSP, ONVIF) usando una lista pública y conocida de
   credenciales por defecto documentadas por los propios fabricantes.
4. Reporte: genera un JSON/CSV con IP, puerto, protocolo, marca estimada
   y si una credencial por defecto funcionó (sin guardar ni exponer nada
   más allá de eso).


## Licencia

MIT — ver [LICENSE](LICENSE). Uso bajo tu propia responsabilidad y siempre
dentro de un marco legal y autorizado.
