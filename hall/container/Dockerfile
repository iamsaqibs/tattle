# Throwaway image for the Hall of Shame batch. Contains Node, the packed Tattle tarball and nothing
# else: third-party tools are installed at run time, inside the container, by batch.sh.
FROM node:22-bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates git procps \
    && rm -rf /var/lib/apt/lists/*
COPY tattle.tgz /tmp/tattle.tgz
RUN npm install -g /tmp/tattle.tgz && rm /tmp/tattle.tgz && tattle --version
COPY batch.sh /usr/local/bin/hall-batch
COPY tools.json /opt/hall/tools.json
RUN chmod +x /usr/local/bin/hall-batch
WORKDIR /work
ENTRYPOINT ["/usr/local/bin/hall-batch"]
