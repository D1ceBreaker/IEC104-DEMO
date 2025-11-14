

# IEC-104 client demo using iec-104 library
# This client connects to an IEC-104 server, activates the session, sends a general interrogation (C_IC_NA_1), and logs all frames.
# All IEC-104 logic is handled by the library for clarity and reliability.

import os
from iec104.client import Client

SERVER_HOST = os.environ.get('SERVER_HOST', '127.0.0.1')
SERVER_PORT = 2404

def log(message):
    print(f"[CLIENT] {message}")

def on_connect():
    log("Connection established. Activating session...")

def on_activate():
    log("IEC-104 session activated. Sending general interrogation command...")
    # Send general interrogation command (C_IC_NA_1)
    client.send_interrogation(common_addr=1)

def on_interrogation_response(asdu):
    # Log received ASDU with mock data
    log(f"Received interrogation response: {asdu}")

def on_frame(frame):
    # Log all IEC-104 frames
    log(f"Frame: {frame}")

def on_error(exc):
    log(f"Error: {exc}")

if __name__ == "__main__":
    # Create IEC-104 client
    client = Client(SERVER_HOST, SERVER_PORT)
    client.on_connect = on_connect
    client.on_activate = on_activate
    client.on_interrogation_response = on_interrogation_response
    client.on_frame = on_frame
    client.on_error = on_error

    log(f"Connecting to server {SERVER_HOST}:{SERVER_PORT}...")
    client.connect()
