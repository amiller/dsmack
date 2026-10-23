"""Use the actual runner's image resolver against the in-guest Docker daemon."""
import json
import subprocess
import sys
from dsmack_compose_runner.identity import ensure_image

class DockerControl:
    def run(self, argv, timeout_s=120):
        result = subprocess.run(argv, capture_output=True, timeout=min(timeout_s, 120))
        return result.returncode, result.stdout, result.stderr

def resolve(ref):
    return ensure_image(DockerControl(), ref, {'architecture': 'arm64', 'os': 'linux'})

if __name__ == '__main__':
    print(json.dumps(resolve(sys.argv[1]), sort_keys=True, separators=(',', ':')))
