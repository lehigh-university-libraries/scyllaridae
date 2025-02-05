ARG TAG=main
ARG DOCKER_REPOSITORY=lehighlts
FROM ${DOCKER_REPOSITORY}/scyllaridae:${TAG} AS scyllaridae
FROM pandoc/latex:3.6-ubuntu@sha256:e9bacab9b10564213fffdb66fc539ddc11d52e1e7d538b1ee356020cb28fa081 AS pandoc

# hadolint ignore=DL3008
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        curl \
        bash=5.2.21-2ubuntu4 \
        gosu=1.17-1ubuntu0.24.04.2 \
        jq=1.7.1-3build1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=scyllaridae /app/scyllaridae /app/scyllaridae
COPY --from=scyllaridae /app/docker-entrypoint.sh /app/docker-entrypoint.sh
COPY scyllaridae.yml .

RUN groupadd -r nobody && \
    useradd -r -g nobody scyllaridae

ENTRYPOINT ["/bin/bash"]
CMD ["/app/docker-entrypoint.sh"]
