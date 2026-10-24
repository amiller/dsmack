ARG BROWSER_BASE
FROM ${BROWSER_BASE}
WORKDIR /opt/checker
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund && npm cache clean --force
ENV HOME=/tmp/home
USER pwuser
ENTRYPOINT ["node"]
