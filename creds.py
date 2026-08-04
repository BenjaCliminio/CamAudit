"""
Credenciales por defecto conocidas para cámaras IP.

Esta lista se compone de credenciales publicadas por los propios
fabricantes en sus manuales de usuario, no de credenciales filtradas ni obtenidas de brechas de datos.

Formato: (usuario, contraseña, marca_estimada)
"""

DEFAULT_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", ""),
    ("admin", "1234"),
    ("admin", "12345"),
    ("admin", "123456"),
    ("admin", "password"),
    ("root", "root"),
    ("root", ""),
    ("root", "pass"),
    ("user", "user"),
    ("guest", "guest"),
    ("admin", "hikvision"),
    ("888888", "888888"),
    ("666666", "666666"),
    ("admin", "foscam"),
    ("admin", "admin1234"),
    ("admin", "admin@123"),
]


def credentials_for_brand(brand: str):
    """Devuelve primero las credenciales de la marca estimada y después
    el resto, para probar las más probables primero."""
    brand = (brand or "").lower()
    specific = [c for c in DEFAULT_CREDENTIALS if c[2] == brand]
    rest = [c for c in DEFAULT_CREDENTIALS if c[2] != brand]
    return specific + rest