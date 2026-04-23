from __future__ import annotations

import signal
import sys
import time

running = True


def _handle_term(signum, frame):
    global running
    print("backend-stop", flush=True)
    running = False


signal.signal(signal.SIGTERM, _handle_term)
signal.signal(signal.SIGINT, _handle_term)

print("backend-start", flush=True)
while running:
    print("heartbeat", flush=True)
    time.sleep(0.2)

sys.exit(0)
