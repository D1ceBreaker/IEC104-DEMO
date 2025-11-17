# server/server.py
import c104
import time
import threading

def sv_on_connect(server: c104.Server, ip: str) -> bool:
    print(f"[SV] Accepting connection from {ip}")
    return True  # Accept all for demo

def sv_on_receive_raw(server: c104.Server, data: bytes) -> None:
    print(f"[SV] RX: {data.hex()} | {c104.explain_bytes(apdu=data)}")

def sv_on_send_raw(server: c104.Server, data: bytes) -> None:
    print(f"[SV] TX: {data.hex()} | {c104.explain_bytes(apdu=data)}")

# Create and configure server
server = c104.Server(ip="0.0.0.0", port=2404, tick_rate_ms=100)
server.on_connect(sv_on_connect)
server.on_receive_raw(sv_on_receive_raw)
server.on_send_raw(sv_on_send_raw)

# Add station and point
station = server.add_station(common_address=1)
point = station.add_point(io_address=100, type=c104.Type.M_SP_NA_1)

# Start server
server.start()
print("[SV] Server running on 0.0.0.0:2404")

# Update point in background
def update_loop():
    val = False
    while True:
        val = not val
        point.value = val
        print(f"[SV] Point 100 = {val}")
        time.sleep(2)

threading.Thread(target=update_loop, daemon=True).start()

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("\n[SV] Shutting down...")
finally:
    server.stop()