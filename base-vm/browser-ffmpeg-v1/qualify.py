"""Offline container media checks; not native full14 or publication approval."""
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
from PIL import Image

image_id, output = sys.argv[1:]
if not image_id.startswith('sha256:') or len(image_id) != 71:
    raise SystemExit('expected externally selected image config digest')
r = Path(output)
r.mkdir(mode=0o700)
colors = [(220, 10, 20), (10, 220, 20), (10, 20, 220), (220, 180, 20)]
frames = bytearray()
for color in colors:
    stream = io.BytesIO()
    Image.new('RGB', (64, 64), color).save(stream, format='JPEG', quality=90)
    frames += stream.getvalue()
(r / 'four.mjpeg').write_bytes(frames)
(r / 'invalid.mjpeg').write_bytes(b'not a jpeg\n')
base = ['docker', 'run', '--rm', '--network', 'none', '--read-only',
        '--user', '1000:1000', '--cpus', '2', '--memory', '512m',
        '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
        '--tmpfs', '/tmp:rw,nosuid,nodev,size=32m',
        '-v', str(r.resolve()) + ':/control:rw', '--entrypoint',
        '/ms-playwright/ffmpeg-1013/ffmpeg-linux', image_id]
checks = []
def run(label, argv, success=True):
    p = subprocess.run(base + argv, capture_output=True, timeout=45)
    (r / (label + '.stdout')).write_bytes(p.stdout)
    (r / (label + '.stderr')).write_bytes(p.stderr)
    if (p.returncode == 0) != success:
        raise RuntimeError(label + ' unexpected exit ' + str(p.returncode))
    checks.append({'name': label, 'exit_code': p.returncode})
    return p.stdout + p.stderr
version = run('version', ['-version'])
if b'7.0.1-dsmack-source-v1' not in version:
    raise RuntimeError('wrong executable version')
protocols = run('protocols', ['-protocols']).decode().splitlines()
if any(x.strip() in {'http', 'https', 'tcp', 'tls', 'udp'} for x in protocols):
    raise RuntimeError('unexpected network protocol')
run('encode', ['-v', 'error', '-f', 'image2pipe', '-framerate', '25', '-c:v', 'mjpeg', '-i',
    '/control/four.mjpeg', '-c:v', 'libvpx-vp9', '-deadline', 'realtime',
    '-cpu-used', '8', '/control/four.webm'])
run('decode', ['-v', 'error', '-i', '/control/four.webm', '-f', 'image2',
    '/control/frame-%02d.png'])
files = sorted(r.glob('frame-*.png'))
if len(files) != 4:
    raise RuntimeError('wrong decoded frame count')
for p, color in zip(files, colors):
    with Image.open(p) as im:
        if im.size != (64, 64):
            raise RuntimeError('wrong dimensions')
        pixel = im.convert('RGB').getpixel((32, 32))
        if max(abs(a-b) for a, b in zip(pixel, color)) > 12:
            raise RuntimeError('wrong decoded colors')
run('malformed', ['-v', 'error', '-f', 'image2pipe', '-c:v', 'mjpeg', '-i', '/control/invalid.mjpeg',
    '-c:v', 'libvpx-vp9', '/control/invalid.webm'], False)
run('network-refusal', ['-v', 'error', '-i', 'https://example.invalid/file',
    '/control/network.webm'], False)
result = {'image_id': image_id, 'checks': checks, 'decoded_frames': 4,
          'webm_sha256': hashlib.sha256((r / 'four.webm').read_bytes()).hexdigest(),
          'scope': 'ARM64 container under host emulation, offline media checks only',
          'native_full14_qualified': False, 'publication_authorized': False}
(r / 'RESULT.json').write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps(result))
