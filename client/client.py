import c104
import socket
import os
import time
import threading

known_points = {}
stop_event = threading.Event()

def cl_on_new_station(client: c104.Client, connection: c104.Connection, common_address: int) -> None:
    print(f"[CL] Discovered station {common_address}")
    connection.add_station(common_address=common_address)

def cl_on_new_point(client: c104.Client, station: c104.Station, io_address: int, point_type: c104.Type) -> None:
    print(f"[CL] New point IOA={io_address}, type={point_type}")
    point = station.add_point(io_address=io_address, type=point_type)

    def on_receive(point: c104.Point, previous_info: c104.Information, message: c104.IncomingMessage) -> c104.ResponseState:
        prev_val = getattr(previous_info, "value", None)
        print(
            f"[CL] Rx {point.type.name} CA={point.station.common_address} IOA={point.io_address} "
            f"COT={message.cot.name} val={point.value} prev={prev_val}"
        )
        return c104.ResponseState.SUCCESS

    point.on_receive(on_receive)
    key = (station.common_address, io_address)
    known_points[key] = {
        "point": point,
        "last_value": point.value
    }

def cl_on_station_initialized(client: c104.Client, station: c104.Station, cause: c104.Coi) -> None:
    print(f"[CL] Station {station.common_address} initialized (cause: {cause})")

client = c104.Client(tick_rate_ms=100)
client.on_new_station(cl_on_new_station)
client.on_new_point(cl_on_new_point)
# Some c104 builds do not expose on_station_initialized; guard to avoid AttributeError.
if hasattr(client, "on_station_initialized"):
    client.on_station_initialized(cl_on_station_initialized)

SERVER_HOST = "127.0.0.1" #os.getenv("IEC104_SERVER_HOST", "iec104-server")
try:
    server_ip = socket.gethostbyname(SERVER_HOST)
    print(f"[CL] Resolved server to {server_ip}")
except socket.gaierror as e:
    raise RuntimeError(f"Cannot resolve {SERVER_HOST}") from e

conn = client.add_connection(ip=server_ip, port=2404)
if not conn:
    raise RuntimeError("Failed to connect")

def con_on_receive_raw(connection: c104.Connection, data: bytes) -> None:
    try:
        explained = c104.explain_bytes(apdu=data)
    except Exception:
        explained = "?"
    print(f"[CL] --> {explained} [{data.hex()}] | CON {connection.ip}:{connection.port}")


def con_on_send_raw(connection: c104.Connection, data: bytes) -> None:
    try:
        explained = c104.explain_bytes(apdu=data)
    except Exception:
        explained = "?"
    print(f"[CL] <-- {explained} [{data.hex()}] | CON {connection.ip}:{connection.port}")


conn.on_receive_raw(con_on_receive_raw)
conn.on_send_raw(con_on_send_raw)

client.start()
print("[CL] Client started")

def wait_connected(timeout_s: float = 10.0) -> bool:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if conn.is_connected:
            return True
        time.sleep(0.05)
    return False


def wait_for_values(ca: int, ioas: list, expected: list, timeout_s: float = 5.0, tol: float = 0.02) -> bool:
    """
    Wait until all points (ca, ioa) exist in known_points and their values match expected within tol.
    Returns True if satisfied before timeout, else False.
    """
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        ok = True
        for ioa, exp in zip(ioas, expected):
            info = known_points.get((ca, ioa))
            if not info:
                ok = False
                break
            val = info["point"].value
            try:
                if abs(float(val) - float(exp)) > tol:
                    ok = False
                    break
            except Exception:
                ok = False
                break
        if ok:
            return True
        time.sleep(0.05)
    return False


def run_command_sequence() -> None:
    if not wait_connected():
        print("[CL] Connection did not become active in time")
        stop_event.set()
        return

    # Ensure station exists on the connection (so we can add command points)
    station = conn.get_station(common_address=1) or conn.add_station(common_address=1)
    if not station:
        raise RuntimeError("Cannot create/get station CA=1 on connection")

    # Command points: separate IOA range to avoid conflict with monitoring IOAs.
    p_sc = station.add_point(io_address=4000, type=c104.Type.C_SC_NA_1)
    p_se = station.add_point(io_address=4001, type=c104.Type.C_SE_NC_1)
    p_dc = station.add_point(io_address=4003, type=c104.Type.C_DC_NA_1)
    p_se_na = station.add_point(io_address=4004, type=c104.Type.C_SE_NA_1)
    p_se_nb = station.add_point(io_address=4005, type=c104.Type.C_SE_NB_1)
    try:
        p_rp = station.add_point(io_address=4002, type=c104.Type.C_RP_NA_1)
    except ValueError:
        p_rp = None
        print("[CL] NOTE: C_RP_NA_1 is not supported as a Point type in this c104 build; skipping IOA=4002")

    print("[CL] Starting command sequence (a.py-equivalent semantics)")

    # 1) Interrogation (C_IC_NA_1, QOI=STATION (20))
    ok = conn.interrogation(common_address=1, cause=c104.Cot.ACTIVATION, qualifier=c104.Qoi.STATION, wait_for_response=True)
    print(f"[CL] TX interrogation(C_IC_NA_1,QOI=STATION) -> {'ok' if ok else 'fail'}")
    time.sleep(0.2)

    # 2) Single command (C_SC_NA_1)
    if p_sc:
        p_sc.value = True
        ok = p_sc.transmit(cause=c104.Cot.ACTIVATION)
        print(f"[CL] TX C_SC_NA_1 IOA=4000 val=True -> {'ok' if ok else 'fail'}")
    time.sleep(0.2)

    # 3) Setpoint command float (C_SE_NC_1)
    if p_se:
        p_se.value = 123.45
        ok = p_se.transmit(cause=c104.Cot.ACTIVATION)
        print(f"[CL] TX C_SE_NC_1 IOA=4001 val=123.45 -> {'ok' if ok else 'fail'}")
    time.sleep(0.2)

    # 3b) Double command (C_DC_NA_1) - extra control command for Suricata rules
    if p_dc:
        # C_DC_NA_1 expects a c104.Double enum value (OFF/ON/INTERMEDIATE/INDETERMINATE).
        p_dc.value = c104.Double.ON
        ok = p_dc.transmit(cause=c104.Cot.ACTIVATION)
        print(f"[CL] TX C_DC_NA_1 IOA=4003 val=ON -> {'ok' if ok else 'fail'}")
    time.sleep(0.2)

    # 3c) Setpoint normalized/scaled (C_SE_NA_1 / C_SE_NB_1) - extra setpoint commands for Suricata rules
    if p_se_na:
        # C_SE_NA_1 expects a c104.NormalizedFloat instance, not a raw float.
        p_se_na.value = c104.NormalizedFloat(0.5)
        ok = p_se_na.transmit(cause=c104.Cot.ACTIVATION)
        print(f"[CL] TX C_SE_NA_1 IOA=4004 val=0.5 -> {'ok' if ok else 'fail'}")
    time.sleep(0.2)

    if p_se_nb:
        # C_SE_NB_1 expects an Int16 value wrapper.
        p_se_nb.value = c104.Int16(1234)
        ok = p_se_nb.transmit(cause=c104.Cot.ACTIVATION)
        print(f"[CL] TX C_SE_NB_1 IOA=4005 val=1234 -> {'ok' if ok else 'fail'}")
    time.sleep(0.2)

    # 4) Clock synchronization (C_CS_NA_1)
    ok = conn.clock_sync(common_address=1, wait_for_response=True)
    print(f"[CL] TX clock_sync(C_CS_NA_1) -> {'ok' if ok else 'fail'}")
    time.sleep(0.2)

    # 5) Test command (C_TS_NA_1)
    # Use with_time=False to send C_TS_NA_1 (TypeID 104), matching rules.txt.
    ok = conn.test(common_address=1, with_time=False, wait_for_response=True)
    print(f"[CL] TX test(C_TS_NA_1) -> {'ok' if ok else 'fail'}")
    time.sleep(0.2)

    # 6) Reset process (C_RP_NA_1) - send QRP=1 (general reset) as integer
    if p_rp:
        p_rp.value = 1
        ok = p_rp.transmit(cause=c104.Cot.ACTIVATION)
        print(f"[CL] TX C_RP_NA_1 IOA=4002 qrp=1 -> {'ok' if ok else 'fail'}")
    else:
        print("[CL] TX C_RP_NA_1 skipped (unsupported Point type)")

    # Keep connection open until the server finishes its scripted monitoring sequence.
    # Otherwise server-side transmit() for IOA=3000..3002 may fail due to disconnect.
    ioas = [3000, 3001, 3002]
    expected = [1.23, 4.56, 7.89]
    if wait_for_values(ca=1, ioas=ioas, expected=expected, timeout_s=6.0):
        print("[CL] Observed meas_second (IOA=3000..3002); disconnecting")
    else:
        print("[CL] Timeout waiting for meas_second (IOA=3000..3002); disconnecting anyway")
    stop_event.set()


threading.Thread(target=run_command_sequence, daemon=True).start()

try:
    while not stop_event.is_set():
        for key, info in known_points.items():
            current = info["point"].value
            last = info["last_value"]
            if current != last:
                ca, ioa = key
                print(f"[CL] Station {ca}, Point {ioa}: {last} → {current}")
                info["last_value"] = current
        time.sleep(0.5)
except KeyboardInterrupt:
    pass
finally:
    client.stop()