import win32evtlog

# Canal de eventos (Security en Windows)
server = 'localhost'
logtype = 'Security'

def analizar_eventos():
    # Abrir el log de eventos
    hand = win32evtlog.OpenEventLog(server, logtype)

    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    total = 0
    eventos_detectados = []

    while True:
        events = win32evtlog.ReadEventLog(hand, flags, 0)
        if not events:
            break
        for ev_obj in events:
            # EventID 4625 = Failed logon
            if ev_obj.EventID == 4625:
                total += 1
                eventos_detectados.append(ev_obj)

    print("=== Reporte de intentos de inicio de sesión fallidos (Windows) ===")
    print(f"Total de eventos encontrados: {total}")

    # Mostrar los últimos 5 eventos
    for e in eventos_detectados[:5]:
        print(f"\nFecha: {e.TimeGenerated}")
        print(f"Origen: {e.SourceName}")
        print(f"Usuario: {e.StringInserts[5] if len(e.StringInserts) > 5 else 'N/A'}")
        print(f"IP: {e.StringInserts[18] if len(e.StringInserts) > 18 else 'N/A'}")

if __name__ == "__main__":
    analizar_eventos()
