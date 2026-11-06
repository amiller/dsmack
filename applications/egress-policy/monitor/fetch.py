"""Fetch only Meta's pinned upstream artifacts; uses HF_TOKEN if explicitly supplied."""
import os
from pathlib import Path
import sys
import urllib.request
from promptguard import REGISTRY, verify_files

directory = Path(sys.argv[1])
directory.mkdir(parents=True, exist_ok=True)
policy = REGISTRY['baseline-pg2']
for name in policy['files']:
    request = urllib.request.Request(f"https://huggingface.co/{policy['model']}/resolve/{policy['revision']}/{name}")
    if os.environ.get('HF_TOKEN'):
        request.add_header('Authorization', 'Bearer ' + os.environ['HF_TOKEN'])
    with urllib.request.urlopen(request) as response, (directory / name).open('wb') as output:
        import shutil
        shutil.copyfileobj(response, output)
verify_files(directory)
