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

