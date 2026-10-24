# Linux run-result verifier

`../verifier-browser/` is the server-side verifier for Mac runs. It authenticates
the App Attest launch and result assertions, the guest receipt and statement,
extracts the result disk in a Linux namespace sandbox and checks the retained
outputs, then signs a report. It imports the compose contract library from
`base-vm/browser-sandbox-v1/source/runner-content/lib` and the App Attest core
from `verifier/core.py`, so run it from a full checkout.

`verify.py` is the launcher:

```text
V="/usr/bin/python3 -I verifier-browser/verify.py"
$V operator enroll ...           # App Attest enrollment ceremony
$V operator issue-challenge ...  # fresh replay challenge
$V prepare prepare --app-out DIR --enrollment FILE --context FILE --bundle NEW_DIR
$V prepare verify --bundle DIR --context FILE --retained NEW_DIR ...
$V operator check ...            # relying-party check of a signed report
```

`applications/arcade-pilot/runner/server_adapter.py` and `authority.py` show the
exact arguments used by the live Arcade service.
