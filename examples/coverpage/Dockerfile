ARG TAG=main
ARG DOCKER_REPOSITORY=local
FROM ${DOCKER_REPOSITORY}/scyllaridae:${TAG} AS scyllaridae
FROM pandoc/latex:3.2.0 AS pandoc

RUN apk update && \
    apk add --no-cache \
      bash==5.2.21-r0 \
      curl==8.5.0-r0 \
      ghostscript==10.03.1-r0 \
      jq==1.7.1-r0

WORKDIR /app
COPY --from=scyllaridae /app/scyllaridae /app/scyllaridae
COPY --from=scyllaridae /app/docker-entrypoint.sh /app/docker-entrypoint.sh
COPY . /app

ENTRYPOINT ["/bin/bash"]
CMD ["/app/docker-entrypoint.sh"]
