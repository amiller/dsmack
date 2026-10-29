#!/usr/bin/env bash
set -euo pipefail
# Run on zed, with this directory copied to an otherwise empty lane directory.
root=$(cd "$(dirname "$0")" && pwd)
image=abalone-browser-recorder:spike-20261011
name=dsmack-webapp-w4-recorder-r5-20261029
mkdir "$root/output"
docker image inspect "$image" --format '{{.Id}}' > "$root/output/recorder-image.txt"
trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT
timeout --signal=TERM --kill-after=15 600 docker run --rm --name "$name" \
  --user "$(id -u):$(id -g)" --cpus 2 --memory 2g --pids-limit 256 \
  --shm-size 256m --tmpfs /tmp:rw,nosuid,size=512m --read-only \
  --cap-drop ALL --security-opt no-new-privileges \
  --ulimit fsize=65000000:65000000 \
  --mount "type=bind,src=$root/journey.mjs,dst=/input/journey.mjs,readonly" \
  --mount "type=bind,src=$root/output,dst=/output" \
  -e DISPLAY=:99 -e EVIDENCE=/output \
  -e XDG_CONFIG_HOME=/tmp/config -e XDG_CACHE_HOME=/tmp/cache \
  -e PLAYWRIGHT_MODULE=/opt/browser-mcp/node_modules/playwright/index.mjs \
  --entrypoint bash "$image" -c '
    set -euo pipefail
    Xvfb :99 -screen 0 1440x1100x24 -nolisten tcp >/tmp/xvfb.log 2>&1 &
    for n in $(seq 1 50); do test -S /tmp/.X11-unix/X99 && break; sleep .1; done
    ffmpeg -nostdin -loglevel error -f x11grab -video_size 1440x1100 \
      -framerate 6 -i :99 -an -c:v libx264 -preset ultrafast -crf 31 \
      -t 570 -fs 60000000 /output/continuous.mp4 >/output/recorder.log 2>&1 &
    capture=$!
    trap '\''kill -INT "$capture" 2>/dev/null || true; wait "$capture" || true'\'' EXIT
    node /input/journey.mjs
  ' > "$root/output/run.log" 2>&1
test "$(du -sb "$root/output" | cut -f1)" -lt 100000000
