ARG COMPUTE_IMAGE=compute-node
FROM ${COMPUTE_IMAGE}
USER root
RUN apt-get update && apt-get install -y --no-install-recommends python3-venv libseccomp2 \
 && rm -rf /var/lib/apt/lists/*
COPY applications/egress-policy/monitor /opt/monitor
RUN python3 -m venv /opt/monitor/venv \
 && /opt/monitor/venv/bin/pip install --no-cache-dir --index-url https://download.pytorch.org/whl/cpu torch==2.7.1 \
 && /opt/monitor/venv/bin/pip install --no-cache-dir -r /opt/monitor/requirements.txt \
 && python3 -c 'import sys; from pathlib import Path; sys.path.insert(0,"/opt/monitor"); from promptguard import verify_files; verify_files(Path("/opt/monitor/weights"))' \
 && chmod -R a+rX /opt/monitor
