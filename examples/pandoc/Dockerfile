ARG TAG=main
ARG DOCKER_REPOSITORY=lehighlts
FROM ${DOCKER_REPOSITORY}/scyllaridae:${TAG} AS scyllaridae
FROM pandoc/latex:3.7-ubuntu@sha256:81709b6006365244469655dd066e8e3b6dd7f0d5ce606135b638ac08cd89e261 AS pandoc

# renovate: datasource=repology depName=ubuntu_24_04/gosu
ENV CURL_VERSION="8.5.0-2ubuntu10.6"
# renovate: datasource=repology depName=ubuntu_24_04/gosu
ENV BASH_VERSION="5.2.21-2ubuntu4"
# renovate: datasource=repology depName=ubuntu_24_04/gosu
ENV GOSU_VERSION="1.17-1ubuntu0.24.04.2"
# renovate: datasource=repology depName=ubuntu_24_04/jq
ENV JQ_VERSION="1.7.1-3build1"

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        curl="${CURL_VERSION}" \
        bash="${BASH_VERSION}" \
        gosu="${GOSU_VERSION}" \
        jq="${JQ_VERSION}" \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=scyllaridae /app/scyllaridae /app/scyllaridae
COPY --from=scyllaridae /app/docker-entrypoint.sh /app/docker-entrypoint.sh
COPY scyllaridae.yml .

RUN groupadd -r nobody && \
    useradd -r -g nobody scyllaridae

ENTRYPOINT ["/bin/bash"]
CMD ["/app/docker-entrypoint.sh"]
