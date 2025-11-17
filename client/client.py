# client/client.py
import c104
import time

def cl_on_new_station(client: c104.Client, connection: c104.Connection, common_address: int) -> None:
    print(f"[CL] New station: {common_address}")
    connection.add_station(common_address=common_address)

def cl_on_new_point(client: c104.Client, station: c104.Station, io_address: int, point_type: c104.Type) -> None:
    print(f"[CL] New point: IOA={io_address}, Type={point_type}")
    point = station.add_point(io_address=io_address, type=point_type)
    def on_update(p: c104.Point, old, new) -> None:
        print(f"[CL] Point {io_address} updated: {old} → {new}")
    point.on_update = on_update

def cl_on_station_initialized(client: c104.Client, station: c104.Station, cause: c104.Coi) -> None:
    print(f"[CL] Station {station.common_address} initialized (cause: {cause})")

client = c104.Client(tick_rate_ms=100)
client.on_new_station(cl_on_new_station)
client.on_new_point(cl_on_new_point)
client.on_station_initialized(cl_on_station_initialized)

conn = client.add_connection(ip="iec104-server", port=2404)
if not conn:
    raise RuntimeError("Failed to add connection")

print("[CL] Starting client...")
client.start()

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    pass
finally:
    client.stop()