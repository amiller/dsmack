# Coordinator supplies an independently resolved official Node24 digest.
ARG NODE_IMAGE
FROM ${NODE_IMAGE}
WORKDIR /app
COPY applications/bounties/service ./service
COPY applications/bounties/examples/arcade/web ./examples/arcade/web
COPY applications/bounties/chain ./chain
# Reviewed cast executable is a public build input; config pins its SHA256.
COPY cast /usr/local/bin/cast
ENV ARCADE_CONFIG=/data/config.json
EXPOSE 8080
CMD ["node", "service/server.mjs"]
