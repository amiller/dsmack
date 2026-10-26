FROM scratch
COPY dsmack-peer-amd64 /dsmack-peer
ENTRYPOINT ["/dsmack-peer"]
