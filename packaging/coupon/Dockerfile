FROM rust:1.94-bookworm@sha256:6ae102bdbf528294bc79ad6e1fae682f6f7c2a6e6621506ba959f9685b308a55 AS finality
WORKDIR /src
COPY runner/chain/ethereum-finality/Cargo.toml runner/chain/ethereum-finality/Cargo.lock ./
COPY runner/chain/ethereum-finality/src/main.rs src/main.rs
RUN cargo build --locked && strip target/debug/dsmack-ethereum-finality

FROM node:24.15.0-bookworm@sha256:f22d6a1f082c02f292e86929b5b0442ac2e5eaf438a5dea9b1566601c3e05940
ARG TARGETARCH
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /opt/dsmack
COPY node/coupon-node.mjs node/coupon-live-node.mjs node/
COPY --from=finality /src/target/debug/dsmack-ethereum-finality bin/dsmack-ethereum-finality
ARG COUPON_APPROVAL_PUBLIC_KEY
COPY packaging/coupon/approval-root.json packaging/coupon/approval-root.json
RUN if [ -n "$COUPON_APPROVAL_PUBLIC_KEY" ]; then node -e 'const fs=require("fs");const key=process.argv[1];if(!/^[0-9a-f]{64}$/.test(key))process.exit(1);fs.writeFileSync("packaging/coupon/approval-root.json",JSON.stringify({public_key_hex:key})+"\n");fs.chmodSync("packaging/coupon/approval-root.json",0o444);' "$COUPON_APPROVAL_PUBLIC_KEY"; fi
COPY experiments/coupon_redemption/__init__.py experiments/coupon_redemption/evidence.py experiments/coupon_redemption/near.py experiments/coupon_redemption/offer_v2.py experiments/coupon_redemption/offer_v3.py experiments/coupon_redemption/offer_v4.py experiments/coupon_redemption/dstack_issuer_identity.py experiments/coupon_redemption/dstack_bootstrap.py experiments/coupon_redemption/live_worker.py experiments/coupon_redemption/staging_approval.py experiments/coupon_redemption/issuance_guard.py experiments/coupon_redemption/async_service_v4.py experiments/coupon_redemption/issuer_service.py experiments/coupon_redemption/peer_worker.py experiments/coupon_redemption/service.py experiments/coupon_redemption/service_v2.py experiments/coupon_redemption/service_v3.py experiments/coupon_redemption/service_v4.py experiments/coupon_redemption/spike.py experiments/coupon_redemption/transport.py experiments/coupon_redemption/peer_bridge.mjs experiments/coupon_redemption/
COPY experiments/coupon_redemption/fixtures/offer-v2.json experiments/coupon_redemption/fixtures/offer-v3.json experiments/coupon_redemption/fixtures/
COPY packaging/coupon/README.md packaging/coupon/smoke.mjs packaging/coupon/paired-source.json packaging/coupon/python-wheels.json packaging/coupon/install_python.py packaging/coupon/python-worker packaging/coupon/
COPY vendor/abalone/package.json vendor/abalone/package-lock.json vendor/abalone/
COPY vendor/abalone/lib/p2p.mjs vendor/abalone/lib/appattest.mjs vendor/abalone/lib/config.mjs vendor/abalone/lib/macrunner.mjs vendor/abalone/lib/coupon.mjs vendor/abalone/lib/coupon-offer.mjs vendor/abalone/lib/coupon-accountless.mjs vendor/abalone/lib/
COPY vendor/abalone/lib/vendor/macrunner.mjs vendor/abalone/lib/vendor/
COPY vendor/abalone/anchors/apple-app-attestation-root.pem vendor/abalone/anchors/
COPY source-manifest.json ./
RUN test "$TARGETARCH" = amd64 && python3 packaging/coupon/install_python.py \
    && mkdir -p /usr/local/lib/python3.11/dist-packages \
    && cp -a python-deps/. /usr/local/lib/python3.11/dist-packages/ \
    && cd vendor/abalone && npm ci --ignore-scripts --omit=dev --no-audit --no-fund \
    && npm cache clean --force
USER node
ENTRYPOINT ["node", "node/coupon-node.mjs"]
CMD ["--help"]
