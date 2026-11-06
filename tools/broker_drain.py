"""Drain a relay broker before a deploy that restarts it: stop new stays, let running ones finish."""
import json
import time
from urllib.request import Request, urlopen


def drain(base, project, operator_token, *, call=None, sleep=time.sleep):
    def fetch(path, method="GET", headers={}):
        request = Request(base.rstrip('/') + '/' + project + path, method=method, headers=headers)
        with urlopen(request, timeout=10) as response:
            return json.load(response)
    call = call or fetch
    if call('/drain', 'POST', {'Authorization': 'Bearer ' + operator_token}) != {'draining': True}:
        raise RuntimeError("Broker did not confirm draining")
    # A stay lasts at most an hour, so the wait ends without a deadline.
    while True:
        busy = call('/network')['totals']['busy_slots']
        streams = call('/inference/status')['inFlightStreams']
        if type(busy) is not int or busy < 0 or type(streams) is not int or streams < 0:
            raise RuntimeError("Broker must report busy_slots and inFlightStreams before deploying")
        if busy == 0 and streams == 0:
            print("Drain: idle (0 busy guests, 0 model streams)", flush=True)
            return
        print(f"Drain: no new stays; waiting for {busy} busy guests and {streams} model streams", flush=True)
        sleep(5)
