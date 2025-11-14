

# IEC-104 server demo using iec-104 library
# This server accepts IEC-104 connections, activates sessions, and responds to interrogation with simple mock data in a single frame.
# All IEC-104 frames and exchanges are logged for demonstration purposes.

import os
from c104 import Server

IEC104_PORT = 2404

def log(message):
    print(f"[SERVER] {message}")

# Subclass Server to override event methods
class DemoServer(Server):
    def on_connect(self, addr):
        log(f"Client connected: {addr}")

    def on_activate(self, addr):
        log(f"IEC-104 session activated for client: {addr}")

    def on_interrogation(self, addr, common_addr):
        log(f"Received general interrogation request from {addr}, common_addr={common_addr}")
        mock_value = "42"
        asdu = {
            "type_id": 9,              # Measured value
            "cause_tx": 20,            # Response to interrogation
            "common_addr": common_addr,
            "ioa": 1,                  # Information object address
            "value": mock_value        # Mock value (simple string)
        }
        self.send_asdu(addr, asdu)
        log(f"Mock data sent: {asdu}")

    def on_frame(self, addr, frame):
        log(f"Frame from {addr}: {frame}")

    def on_error(self, addr, exc):
        log(f"Error for {addr}: {exc}")

if __name__ == "__main__":
    # Create IEC-104 server (use positional arguments for ip and port)
    server = DemoServer(os.environ.get('SERVER_HOST', '0.0.0.0'), IEC104_PORT)
    log(f"Starting IEC-104 server on port {IEC104_PORT}")
    server.start()
