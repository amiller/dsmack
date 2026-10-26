# Build from the repository root: docker build -f applications/coordinator/Dockerfile .
FROM python@sha256:a0f57064cbdcd6285fa45f51237ab0b35ea8ebaed06a1f5973e89e19dfb86704
RUN pip install --no-cache-dir cryptography==43.0.3 coincurve==21.0.0
COPY trust/apple-app-attestation-root.pem /app/trust/
COPY verifier/__init__.py verifier/core.py verifier/macos_policy.py /app/verifier/
COPY dstack-compat/grant.py dstack-compat/dsmack_dstack.py /app/dstack-compat/
COPY applications/coordinator/coordinator.py /app/applications/coordinator/
CMD ["python3", "-I", "-B", "/app/applications/coordinator/coordinator.py"]
