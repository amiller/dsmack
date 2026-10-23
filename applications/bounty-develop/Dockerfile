# Build only against independently selected CAND7 generator source image.
ARG ADMITTED_DEVELOP_PARENT
FROM ${ADMITTED_DEVELOP_PARENT}
USER root
COPY applications/bounty-develop/core.py applications/bounty-develop/main.py applications/bounty-develop/driver.py /opt/bounty-develop/
RUN test -z "$(find /opt/bounty-develop -name __pycache__ -o -name '*.pyc' -o -name '*.pyo' -o -name '*.so' -o -name '*.pth')" \
 && find /opt/bounty-develop -type f -exec chmod 0444 {} + \
 && chmod 0755 /opt/bounty-develop \
 && test ! -L /usr/bin/python3 \
 && printf '%s  %s\n' b49be8a5e565bf2d45b50d2de62017b25462131acc9425d2fdb98b8f29c9dce2 /usr/local/bin/claude | sha256sum -c -
USER 1000:1000
ENTRYPOINT ["/usr/bin/python3","-I","-B"]
CMD ["/workspace/inputs/driver"]
