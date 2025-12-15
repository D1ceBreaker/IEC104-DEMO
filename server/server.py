import threading
import c104
import time
import datetime

server = c104.Server(ip="0.0.0.0", port=2404, tick_rate_ms=100)
stop_event = threading.Event()


def sv_on_connect(server: c104.Server, ip: str) -> bool:
    print(f"[SV] Connection from {ip}")
    return True


server.on_connect(sv_on_connect)

# Raw APDU logging (helps to correlate with PCAP-like flows)
def sv_on_receive_raw(server: c104.Server, data: bytes) -> None:
    try:
        explained = c104.explain_bytes(apdu=data)
    except Exception:
        explained = "?"
    print(f"[SV] --> {explained} [{data.hex()}] | SERVER {server.ip}:{server.port}")


def sv_on_send_raw(server: c104.Server, data: bytes) -> None:
    try:
        explained = c104.explain_bytes(apdu=data)
    except Exception:
        explained = "?"
    print(f"[SV] <-- {explained} [{data.hex()}] | SERVER {server.ip}:{server.port}")


def sv_on_unexpected_message(server: c104.Server, message: c104.IncomingMessage, cause: c104.Umc) -> None:
    print(
        f"[SV] ->?| unexpected={cause} OA={message.originator_address} "
        f"COT={message.cot} CA={message.common_address} TYPE={message.type}"
    )


def sv_on_clock_sync(server: c104.Server, ip: str, date_time: datetime.datetime) -> c104.ResponseState:
    print(f"[SV] Clock sync from {ip}: {date_time}")
    return c104.ResponseState.SUCCESS


server.on_receive_raw(sv_on_receive_raw)
server.on_send_raw(sv_on_send_raw)
server.on_unexpected_message(sv_on_unexpected_message)
server.on_clock_sync(sv_on_clock_sync)

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

# Command points moved to separate IOA range (to avoid conflicts with monitoring IOAs)
cmd_sc = station.add_point(io_address=4000, type=c104.Type.C_SC_NA_1)
cmd_se = station.add_point(io_address=4001, type=c104.Type.C_SE_NC_1)
try:
    cmd_rp = station.add_point(io_address=4002, type=c104.Type.C_RP_NA_1)
except ValueError:
    # c104==2.0.2 exposes the enum member, but does not support it as a Point type.
    cmd_rp = None
    print("[SV] NOTE: C_RP_NA_1 is not supported as a Point type in this c104 build; skipping IOA=4002")


def sv_on_command(point: c104.Point, previous_info: c104.Information, message: c104.IncomingMessage) -> c104.ResponseState:
    prev_val = getattr(previous_info, "value", None)
    print(
        f"[SV] CMD Rx {point.type.name} CA={point.station.common_address} IOA={point.io_address} "
        f"COT={message.cot.name} val={point.value} prev={prev_val}"
    )
    return c104.ResponseState.SUCCESS


for p in (cmd_sc, cmd_se, cmd_rp):
    if p is not None:
        p.on_receive(sv_on_command)


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

    print("[SV] Monitoring sequence complete; waiting for client command sequence + disconnect")
    while server.has_open_connections and not stop_event.is_set():
        time.sleep(0.2)
    print("[SV] No open connections, stopping server")
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