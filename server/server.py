# server/server.py
import c104
import time
import threading

# Создаём сервер
server = c104.Server(ip="0.0.0.0", port=2404, tick_rate_ms=100)

def sv_on_connect(server: c104.Server, ip: str) -> bool:
    print(f"[SV] Connection from {ip}")
    return True

server.on_connect(sv_on_connect)

# Добавляем станцию и точку
station = server.add_station(common_address=1)
point = station.add_point(io_address=100, type=c104.Type.M_SP_NA_1)

server.start()
print("[SV] Server started")

# Фоновый цикл: каждую секунду переключаем и отправляем
def periodic_update():
    value = False
    while True:
        value = not value
        point.value = value
        # Передаём с причиной "спонтанная передача"
        success = point.transmit(cause=c104.Cot.SPONTANEOUS)
        if success:
            print(f"[SV] Sent point 100 = {value}")
        else:
            print(f"[SV] Failed to send point 100 = {value}")
        time.sleep(1)

threading.Thread(target=periodic_update, daemon=True).start()

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    server.stop()