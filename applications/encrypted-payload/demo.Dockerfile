FROM --platform=linux/arm64 busybox:1.37.0
COPY marker /private/marker
COPY demo.sh /private/demo.sh
ENV PAYLOAD_DOMAIN=encrypted-demo
WORKDIR /private
ENTRYPOINT ["/bin/sh", "/private/demo.sh"]
CMD ["fixed-challenge"]
