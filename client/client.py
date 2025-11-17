# client/client.py
import c104
import socket
import os
import time

# --- Callbacks with correct type annotations ---
def cl_on_new_station(client: c104.Client, connection: c104.Connection, common_address: int) -> None:
    print(f"[CL] Discovered station {common_address}")
    connection.add_station(common_address=common_address)

def cl_on_new_point(client: c104.Client, station: c104.Station, io_address: int, point_type: c104.Type) -> None:
    print(f"[CL] New point IOA={io_address}, type={point_type}")
    point = station.add_point(io_address=io_address, type=point_type)
    point.on_update = lambda p, old, new: print(f"[CL] Point {io_address}: {old} → {new}")

def cl_on_station_initialized(client: c104.Client, station: c104.Station, cause: c104.Coi) -> None:
    print(f"[CL] Station {station.common_address} initialized (cause: {cause})")

# --- Client setup ---
client = c104.Client(tick_rate_ms=100)
client.on_new_station(cl_on_new_station)
client.on_new_point(cl_on_new_point)
client.on_station_initialized(cl_on_station_initialized)

# Read server host from environment variable
SERVER_HOST = os.getenv("IEC104_SERVER_HOST", "iec104-server")  # default for Docker
print(f"[CL] Using server host: {SERVER_HOST}")

# Resolve hostname to IP (required by c104)
try:
    server_ip = socket.gethostbyname(SERVER_HOST)
    print(f"[CL] Resolved to IP: {server_ip}")
except socket.gaierror as e:
    raise RuntimeError(f"Failed to resolve IEC104_SERVER_HOST='{SERVER_HOST}'") from e

# Connect using resolved IP
conn = client.add_connection(ip=server_ip, port=2404)
if not conn:
    raise RuntimeError("Failed to create connection")

client.start()
print("[CL] Client running")

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    pass
finally:
    client.stop()