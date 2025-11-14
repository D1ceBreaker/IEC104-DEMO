

# IEC-104 server demo using iec-104 library
# This server accepts IEC-104 connections, activates sessions, and responds to interrogation with simple mock data in a single frame.
# All IEC-104 frames and exchanges are logged for demonstration purposes.

import os
from iec104.server import Server

IEC104_PORT = 2404

def log(message):
    print(f"[SERVER] {message}")

def on_connect(addr):
    log(f"Client connected: {addr}")

def on_activate(addr):
    log(f"IEC-104 session activated for client: {addr}")

def on_interrogation(addr, common_addr):
    # Log general interrogation request
    log(f"Received general interrogation request from {addr}, common_addr={common_addr}")
    # Send mock data (can be changed for demonstration)
    # ASDU type: 9 (measured value), cause: 20 (response to interrogation), object address: 1, value: "42"
    # Value is sent as a string for simplicity
    mock_value = "42"
    # Create ASDU with mock data
    asdu = {
        "type_id": 9,              # Measured value
        "cause_tx": 20,            # Response to interrogation
        "common_addr": common_addr,
        "ioa": 1,                  # Information object address
        "value": mock_value        # Mock value (simple string)
    }
    server.send_asdu(addr, asdu)
    log(f"Mock data sent: {asdu}")

def on_frame(addr, frame):
    log(f"Frame from {addr}: {frame}")

def on_error(addr, exc):
    log(f"Error for {addr}: {exc}")

if __name__ == "__main__":
    # Create IEC-104 server
    server = Server(host=os.environ.get('SERVER_HOST', '0.0.0.0'), port=IEC104_PORT)
    server.on_connect = on_connect
    server.on_activate = on_activate
    server.on_interrogation = on_interrogation
    server.on_frame = on_frame
    server.on_error = on_error

    log(f"Starting IEC-104 server on port {IEC104_PORT}")
    server.serve_forever()
