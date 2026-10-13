# Cross-builds without emulation: the deps stage runs on the build host and fetches the target's wheels.
# Runner VMs on Apple silicon: docker buildx build --platform linux/arm64 --provenance=false -f apps/coupon-sdk/Dockerfile -o type=oci,dest=coupon-sdk-arm64.oci.tar .
FROM --platform=$BUILDPLATFORM python:3.12-slim AS deps
ARG TARGETARCH
RUN arch=$([ "$TARGETARCH" = arm64 ] && echo aarch64 || echo x86_64) && pip install --no-cache-dir --target /deps --only-binary=:all: \
    --python-version 3.12 --platform manylinux_2_28_$arch --platform manylinux2014_$arch cryptography==43.0.3
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 DSMACK_SOCKET=/var/run/dsmack.sock NEAR_RPC=https://rpc.testnet.near.org
COPY --from=deps /deps /usr/local/lib/python3.12/site-packages
COPY sdk/python/dsmack_sdk /app/dsmack_sdk
COPY apps/coupon-sdk/near_tx.py apps/coupon-sdk/coupon_account.py /app/
WORKDIR /app
ENTRYPOINT ["python", "coupon_account.py"]
CMD ["account"]
