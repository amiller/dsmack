FROM golang:1.27.3 AS build
WORKDIR /src
COPY applications/compute-node/peer ./applications/compute-node/peer
COPY applications/libp2p-attest/peer ./applications/libp2p-attest/peer
COPY applications/payments/guest ./applications/payments/guest
WORKDIR /src/applications/compute-node/peer
RUN CGO_ENABLED=0 go build -trimpath -o /forwarder ./forwarder
FROM scratch
COPY --from=build /forwarder /forwarder
VOLUME /data
ENTRYPOINT ["/forwarder", "-listen", "0.0.0.0:18271", "-key", "/data/transport.key"]
