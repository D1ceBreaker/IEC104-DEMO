## IEC104 lab quick start

### 1) Prepare environment
- Python3.9 required.
```bash
bash setup.sh
```
- Creates `.venv` with python3.9 and installs `requirements.txt`.

### 2) Run server and client together
```bash
bash launch.sh
```
- Launches `server/server.py` in background, waits 1s, then `client/client.py`.
- Both processes are stopped when you terminate the script.

### 3) Command sequence demo (a.py-equivalent semantics via c104)
In addition to the monitoring points transmitted by the server, the client now sends a command sequence similar to `a.py`:
- `C_IC_NA_1` interrogation (QOI=STATION)
- `C_SC_NA_1` single command (ON)
- `C_SE_NC_1` setpoint float (123.45)
- `C_CS_NA_1` clock sync (client OS time)
- `C_TS_NA_1` test
- `C_RP_NA_1` reset process (QRP=1) — note: **not supported as a Point type in `c104==2.0.2`**, so it is skipped in this lab setup

To avoid IOA/type conflicts with monitoring IOAs (`1000..`, `2000..`, `3000..`), command points use a dedicated range:
- `4000`: `C_SC_NA_1`
- `4001`: `C_SE_NC_1`
- `4002`: `C_RP_NA_1` (skipped with `c104==2.0.2`)

Both sides log raw APDUs (`on_send_raw` / `on_receive_raw`) so you can correlate the exchange with a PCAP-like view.

