

# IEC-104 client demo using iec-104 library
# This client connects to an IEC-104 server, activates the session, sends a general interrogation (C_IC_NA_1), and logs all frames.
# All IEC-104 logic is handled by the library for clarity and reliability.

import os
from c104 import Client

SERVER_HOST = os.environ.get('SERVER_HOST', '127.0.0.1')
SERVER_PORT = 2404

def log(message):
    print(f"[CLIENT] {message}")

# Subclass Client to override event methods
class DemoClient(Client):
    def on_connect(self):
        log("Connection established. Activating session...")

    def on_activate(self):
        log("IEC-104 session activated. Sending general interrogation command...")
        # Send general interrogation command (C_IC_NA_1)
        self.send_interrogation(common_addr=1)

    def on_interrogation_response(self, asdu):
        log(f"Received interrogation response: {asdu}")

    def on_frame(self, frame):
        log(f"Frame: {frame}")

    def on_error(self, exc):
        log(f"Error: {exc}")

if __name__ == "__main__":
    # Create IEC-104 client
    client = DemoClient()
    log(f"Starting IEC-104 client...")
    client.start()
