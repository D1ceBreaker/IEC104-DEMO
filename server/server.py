"""Simple IEC104 demo server using the `iec104`/`c104` python bindings.

Run this file and then start the client to see a basic connect/initialization
exchange. The server prints raw send/receive frames and handles an incoming
clock sync command.
"""

import time
import datetime
import random
import c104


def sv_on_connect(server: c104.Server, ip: str) -> bool:
    print(f"[SERVER] Incoming connection request from {ip}")
    # Accept all connections for the demo (be careful in production!)
    return True


def sv_on_receive_raw(server: c104.Server, data: bytes) -> None:
    print("[SERVER] RECV RAW ->", data.hex())
    try:
        print("          ->", c104.explain_bytes(apdu=data))
    except Exception:
        pass


def sv_on_send_raw(server: c104.Server, data: bytes) -> None:
    print("[SERVER] SEND RAW ->", data.hex())
    try:
        print("         <-", c104.explain_bytes(apdu=data))
    except Exception:
        pass


def sv_on_clock_sync(server: c104.Server, ip: str, date_time: datetime.datetime) -> c104.ResponseState:
    print(f"[SERVER] Clock sync from {ip} -> {date_time}")
    return c104.ResponseState.SUCCESS


def main() -> None:
    server = c104.Server(ip="0.0.0.0", port=2404)
    server.on_connect(sv_on_connect)
    server.on_receive_raw(sv_on_receive_raw)
    server.on_send_raw(sv_on_send_raw)
    server.on_clock_sync(sv_on_clock_sync)

    # Add a station that the server will host (common address 1)
    station = server.add_station(common_address=1)
    if station is None:
        print("[SERVER] Failed to add station common_address=1")

    # Add a couple of points and periodic transmit handlers so real IEC104
    # monitoring messages are produced and sent to connected clients.
    try:
        sv_meas = station.add_point(io_address=11, type=c104.Type.M_ME_NC_1, report_ms=2000)
        sv_sp = station.add_point(io_address=1, type=c104.Type.M_SP_NA_1, report_ms=3000)

        def on_meas_autotransmit(point: c104.Point) -> None:
            # random measurement value
            point.value = round(random.uniform(0, 100), 2)

        def on_sp_autotransmit(point: c104.Point) -> None:
            # toggle boolean single point
            point.value = not bool(point.value)

        sv_meas.on_before_auto_transmit(callable=on_meas_autotransmit)
        sv_sp.on_before_auto_transmit(callable=on_sp_autotransmit)
    except Exception as e:
        print("[SERVER] Warning: could not add auto-transmit points:", e)

    try:
        server.start()
        print(f"[SERVER] Listening on {server.ip}:{server.port}")
        # Keep running until Ctrl-C
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("[SERVER] Stopping server")
    finally:
        server.stop()


if __name__ == "__main__":
    main()
