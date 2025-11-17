"""Simple IEC104 demo client using the `iec104`/`c104` python bindings.

Start `server.py` first, then run this client. The client will add a connection
to the server host (controlled by `SERVER_HOST` env var) and print station
initialization events and any new points.
"""

import os
import time
import socket
import c104


def cl_on_new_station(client: c104.Client, connection: c104.Connection, common_address: int) -> None:
    print(f"[CLIENT] New station reported by connection {connection.ip}:{connection.port} -> CA={common_address}")
    # create a local station representation so we can receive points
    connection.add_station(common_address=common_address)


def cl_on_station_initialized(client: c104.Client, station: c104.Station, cause: c104.Coi) -> None:
    print(f"[CLIENT] Station {station.common_address} initialized (cause={cause})")


def cl_on_new_point(client: c104.Client, station: c104.Station, io_address: int, point_type: c104.Type) -> None:
    print(f"[CLIENT] New point: IOA={io_address} type={point_type} from station CA={station.common_address}")
    # Add the point so subsequent updates arrive on the station object
    station.add_point(io_address=io_address, type=point_type)


def main() -> None:
    server_host = os.environ.get("SERVER_HOST", "127.0.0.1")
    client = c104.Client()
    client.on_new_station(cl_on_new_station)
    client.on_station_initialized(cl_on_station_initialized)
    client.on_new_point(cl_on_new_point)

    # Resolve hostname to IP so the c104 library accepts it (it validates IP).
    server_ip = server_host
    try:
        server_ip = socket.gethostbyname(server_host)
        print(f"[CLIENT] Resolved server host '{server_host}' -> {server_ip}")
    except Exception:
        print(f"[CLIENT] Could not resolve '{server_host}', using as-is")

    # Add connection to demo server. Using Init.ALL triggers basic
    # initialization commands during connect. Keep connection reference.
    connection = client.add_connection(ip=server_ip, port=2404, init=c104.Init.ALL)

    # When connection becomes open, make sure monitoring is allowed (unmute)
    def on_state_change(connection: c104.Connection, state: c104.ConnectionState) -> None:
        print(f"[CLIENT] Connection {connection.ip}:{connection.port} state -> {state}")
        try:
            # If open but muted or open, unmute to receive monitoring messages
            if state in (c104.ConnectionState.OPEN, c104.ConnectionState.OPEN_MUTED):
                connection.unmute()
                # request interrogation so server sends current values
                try:
                    connection.interrogation(common_address=1)
                except Exception:
                    pass
        except Exception:
            pass

    if connection:
        connection.on_state_change(callable=on_state_change)

    try:
        client.start()
        print(f"[CLIENT] Client started, connecting to {server_host}:2404")
        # Keep running so user can Ctrl-C to stop
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("[CLIENT] Stopping client")
    finally:
        client.stop()


if __name__ == "__main__":
    main()
