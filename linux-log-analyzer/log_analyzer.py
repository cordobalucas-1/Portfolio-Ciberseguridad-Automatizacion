#Autor: Lucas Córdoba
import re
from collections import Counter

# Ruta del archivo de log (Linux: /var/log/auth.log)
LOG_FILE = "auth.log"

def analizar_logs():
    intentos_fallidos = []

    with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
        for linea in f:
            # Buscar líneas con "Failed password"
            if "Failed password" in linea:
                # Extraer la IP si existe
                ip_match = re.search(r"from ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", linea)
                if ip_match:
                    ip = ip_match.group(1)
                    intentos_fallidos.append(ip)

    # Contador de intentos por IP
    contador = Counter(intentos_fallidos)

    print("=== Reporte de intentos fallidos de acceso ===")
    for ip, cantidad in contador.most_common():
        print(f"IP: {ip} - Intentos: {cantidad}")

if __name__ == "__main__":
    analizar_logs()
