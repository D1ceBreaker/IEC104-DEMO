# client/client.py
import c104
import socket
import os
import time

# Track known points: { (common_address, io_address): point }
known_points = {}

def cl_on_new_station(client: c104.Client, connection: c104.Connection, common_address: int) -> None:
    print(f"[CL] Discovered station {common_address}")
    connection.add_station(common_address=common_address)

def cl_on_new_point(client: c104.Client, station: c104.Station, io_address: int, point_type: c104.Type) -> None:
    print(f"[CL] New point IOA={io_address}, type={point_type}")
    point = station.add_point(io_address=io_address, type=point_type)
    # Store for polling
    key = (station.common_address, io_address)
    known_points[key] = {
        "point": point,
        "last_value": point.value
    }

def cl_on_station_initialized(client: c104.Client, station: c104.Station, cause: c104.Coi) -> None:
    print(f"[CL] Station {station.common_address} initialized (cause: {cause})")

# ---- Setup ----
client = c104.Client(tick_rate_ms=100)
client.on_new_station(cl_on_new_station)
client.on_new_point(cl_on_new_point)
client.on_station_initialized(cl_on_station_initialized)

SERVER_HOST = os.getenv("IEC104_SERVER_HOST", "iec104-server")
try:
    server_ip = socket.gethostbyname(SERVER_HOST)
    print(f"[CL] Resolved server to {server_ip}")
except socket.gaierror as e:
    raise RuntimeError(f"Cannot resolve {SERVER_HOST}") from e

conn = client.add_connection(ip=server_ip, port=2404)
if not conn:
    raise RuntimeError("Failed to connect")

client.start()
print("[CL] Client started")

# Poll known points for value changes
try:
    while True:
        for key, info in known_points.items():
            current = info["point"].value
            last = info["last_value"]
            if current != last:
                ca, ioa = key
                print(f"[CL] Station {ca}, Point {ioa}: {last} → {current}")
                info["last_value"] = current
        time.sleep(0.5)  # Poll every 500ms
except KeyboardInterrupt:
    pass
finally:
    client.stop()