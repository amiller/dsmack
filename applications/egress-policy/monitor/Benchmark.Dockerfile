FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends libseccomp2 \
 && rm -rf /var/lib/apt/lists/* \
 && pip install --no-cache-dir --index-url https://download.pytorch.org/whl/cpu torch==2.7.1
COPY applications/egress-policy/monitor /opt/monitor
RUN pip install --no-cache-dir -r /opt/monitor/requirements.txt \
 && python -c 'import sys; from pathlib import Path; sys.path.insert(0,"/opt/monitor"); from promptguard import verify_files; verify_files(Path("/opt/monitor/weights"))'
WORKDIR /opt/monitor
ENTRYPOINT ["python"]
