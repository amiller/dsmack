"""Drain a relay broker before a deploy that restarts it: stop new stays, let running ones finish."""
import json
import time
from contextlib import contextmanager
from urllib.error import HTTPError
from urllib.request import Request, urlopen


def fetch(base, project, path, method="GET", headers={}):
    request = Request(base.rstrip('/') + '/' + project + path, method=method, headers=headers)
    with urlopen(request, timeout=10) as response:
        return json.load(response)


@contextmanager
def drained(base, project, operator_token, minutes=65, *, call=None, clock=time.monotonic, sleep=time.sleep):
    """Drain, wait for idle, and run the body. Resume offering stays if anything fails before the
    body completes; a successful deploy replaces the process, which starts undrained."""
    call = call or (lambda *a: fetch(base, project, *a))
    auth = {'Authorization': 'Bearer ' + operator_token}
    try:
        # Inside the try: a timed-out POST may still have drained the broker.
        if call('/drain', 'POST', auth) != {'draining': True}:
            raise RuntimeError("Broker did not confirm draining")
    except HTTPError:
        raise  # The broker answered and refused: nothing was drained.
    except BaseException as error:
        resume(call, project, auth, error)
        raise
    try:
        # A stay lasts at most an hour; a Mac still reporting busy after that is stuck.
        deadline = clock() + minutes * 60
        while True:
            busy = call('/network')['totals']['busy_slots']
            streams = call('/inference/status')['inFlightStreams']
            if type(busy) is not int or busy < 0 or type(streams) is not int or streams < 0:
                raise RuntimeError("Broker must report busy_slots and inFlightStreams before deploying")
            if busy == 0 and streams == 0:
                print("Drain: idle (0 busy guests, 0 model streams)", flush=True)
                break
            if clock() >= deadline:
                raise RuntimeError(f"Drain timed out after {minutes} minutes with {busy} busy guests and {streams} model streams")
            print(f"Drain: no new stays; waiting for {busy} busy guests and {streams} model streams", flush=True)
            sleep(5)
        yield
    except BaseException as error:
        resume(call, project, auth, error)
        raise


def resume(call, project, auth, error):
    print(f"Drain: deploy failed ({type(error).__name__}: {error}); resuming new stays", flush=True)
    try:
        resumed = call('/drain', 'DELETE', auth)
    except Exception as undo:
        raise RuntimeError(f"Deploy failed and DELETE /{project}/drain failed ({type(undo).__name__}); "
                           "the broker may still refuse new stays") from error
    if resumed != {'draining': False}:
        raise RuntimeError(f"Deploy failed and the broker did not confirm resuming: {resumed}") from error
