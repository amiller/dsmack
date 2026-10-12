FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 DSMACK_SOCKET=/var/run/dsmack.sock NEAR_RPC=https://rpc.testnet.near.org
RUN pip install --no-cache-dir cryptography==43.0.3
COPY sdk/python/dsmack_sdk /app/dsmack_sdk
COPY apps/coupon-sdk/near_tx.py apps/coupon-sdk/coupon_account.py /app/
WORKDIR /app
ENTRYPOINT ["python", "coupon_account.py"]
CMD ["account"]
