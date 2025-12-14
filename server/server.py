import threading
import c104
import time

server = c104.Server(ip="0.0.0.0", port=2404, tick_rate_ms=100)
stop_event = threading.Event()


def sv_on_connect(server: c104.Server, ip: str) -> bool:
    print(f"[SV] Connection from {ip}")
    return True


server.on_connect(sv_on_connect)

# Station and points matching the scripted IOAs/types.
station = server.add_station(common_address=1)
sp_points = [
    station.add_point(io_address=1000 + i, type=c104.Type.M_SP_NA_1)
    for i in range(5)
]
meas_first = [
    station.add_point(io_address=2000 + i, type=c104.Type.M_ME_NC_1)
    for i in range(3)
]
meas_second = [
    station.add_point(io_address=3000 + i, type=c104.Type.M_ME_NC_1)
    for i in range(3)
]


def wait_for_connection() -> None:
    # has_active_connections is a property, not callable in some versions
    while not server.has_active_connections:
        time.sleep(0.1)


def send_sequence() -> None:
    wait_for_connection()
    print("[SV] Active connection detected, starting scripted sequence")

    # 5×M_SP_NA_1 (single-point info)
    for idx, point in enumerate(sp_points):
        point.value = bool(idx % 2 == 0)
        success = point.transmit(cause=c104.Cot.SPONTANEOUS)
        print(f"[SV] M_SP_NA_1 IOA={point.io_address} -> {point.value} ({'ok' if success else 'fail'})")
        time.sleep(0.2)

    # 3×M_ME_NC_1 (measured value, short float)
    values_first = [12.34, 56.78, 90.12]
    for point, value in zip(meas_first, values_first):
        point.value = float(value)
        success = point.transmit(cause=c104.Cot.SPONTANEOUS)
        print(f"[SV] M_ME_NC_1 IOA={point.io_address} -> {value} ({'ok' if success else 'fail'})")
        time.sleep(0.2)

    print("[SV] Awaiting automatic S-format ack from client (handled by c104)")
    time.sleep(0.5)

    # Another 3×M_ME_NC_1
    values_second = [1.23, 4.56, 7.89]
    for point, value in zip(meas_second, values_second):
        point.value = float(value)
        success = point.transmit(cause=c104.Cot.SPONTANEOUS)
        print(f"[SV] M_ME_NC_1 IOA={point.io_address} -> {value} ({'ok' if success else 'fail'})")
        time.sleep(0.2)

    # Graceful STOPDT/disconnect.
    time.sleep(1)
    print("[SV] Sequence complete, initiating STOPDT/disconnect")
    server.stop()
    stop_event.set()


server.start()
print("[SV] Server started")

threading.Thread(target=send_sequence, daemon=True).start()

try:
    while not stop_event.is_set():
        time.sleep(0.5)
except KeyboardInterrupt:
    print("[SV] Interrupted, stopping server")
    server.stop()