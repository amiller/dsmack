"""Wait for the broker's reported guests and model streams before a shared-runtime update."""
import json
import math
import time
from urllib.request import urlopen
from urllib.error import HTTPError, URLError


def wait_for_idle(base, minutes=10, *, read=None, clock=time.monotonic, sleep=time.sleep):
    if not math.isfinite(minutes) or minutes < 0:
        raise ValueError("idle wait minutes must be nonnegative")
    def fetch(path):
        with urlopen(base.rstrip('/') + '/relay-broker' + path, timeout=10) as response:
            return json.load(response)
    read = read or fetch
    deadline = clock() + minutes * 60
    while True:
        try:
            network, inference = read('/network'), read('/inference/status')
        except (HTTPError, URLError, TimeoutError) as error:
            remaining = deadline - clock()
            detail = f"HTTP {error.code}" if isinstance(error, HTTPError) else type(error).__name__
            print(f"Deploy guard: waiting for broker activity reports ({detail}; {max(0, int(remaining))}s left)", flush=True)
            if remaining <= 0:
                raise RuntimeError("Deploy guard timed out without an activity report; deployment cannot continue") from None
            sleep(min(2, remaining))
            continue
        busy = network['totals']['busy_slots']
        streams = inference.get('inFlightStreams')
        if type(busy) is not int or busy < 0 or type(streams) is not int or streams < 0:
            raise RuntimeError("Broker must report busy_slots and inFlightStreams before deploying")
        if busy == 0 and streams == 0:
            print("Deploy guard: idle (0 busy guests, 0 model streams)", flush=True)
            return
        remaining = deadline - clock()
        print(f"Deploy guard: waiting for {busy} busy guests and {streams} model streams ({max(0, int(remaining))}s left)", flush=True)
        if remaining <= 0:
            raise RuntimeError("Deploy guard timed out; activity must reach idle before continuing")
        sleep(min(2, remaining))
