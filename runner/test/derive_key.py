"""The /key value the spec (notes/abalone-node-interface.md item 5) predicts, recomputed from the KMS master secret.
usage: derive_key.py MASTER_KEY_FILE CDHASH|dev COMPOSE_HASH PATH   (the pre-app derivation, keyed by the build)
       derive_key.py MASTER_KEY_FILE --app APP PATH"""
import sys
from pathlib import Path
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

master, a, b, path = Path(sys.argv[1]).read_bytes(), *sys.argv[2:]
info = f'mac-compose-app-key/1|{b}' if a == '--app' else f'mac-compose-app-key/1|{a}|{b}'
app_key = HKDF(hashes.SHA256(), 32, None, info.encode()).derive(master)
print(HKDF(hashes.SHA256(), 32, None, f'mac-compose-get-key/1|{path}'.encode()).derive(app_key).hex())
