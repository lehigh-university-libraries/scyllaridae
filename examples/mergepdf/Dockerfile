ARG TAG=main
ARG DOCKER_REPOSITORY=lehighlts
FROM islandora/leptonica:alpine-3.20.2-leptonica-1.84.1-r0@sha256:9e9e46a328d8b55a61a352a6b06ff175f98e40cd5773c9bf93aac58fb56b65f7 AS leptonica
FROM ${DOCKER_REPOSITORY}/scyllaridae-imagemagick:${TAG} AS scyllaridae

# renovate: datasource=repology depName=alpine_3_20/tesseract-ocr
ENV TESSERACT_VERSION="5.3.4-r0"
# renovate: datasource=repology depName=alpine_3_20/jq
ENV JQ_VERSION="1.7.1-r0"
# renovate: datasource=repology depName=alpine_3_20/ghostscript
ENV GHOSTSCRIPT_VERSION="10.05.1-r0"
# renovate: datasource=repology depName=alpine_3_20/poppler-utils
ENV POPPLER_VERSION="24.02.0-r2"

RUN --mount=type=bind,from=leptonica,source=/packages,target=/packages \
    --mount=type=bind,from=leptonica,source=/etc/apk/keys,target=/etc/apk/keys \
    apk update && \
    apk add --no-cache \
        /packages/leptonica-*.apk \
        ghostscript=="${GHOSTSCRIPT_VERSION}" \
        jq=="${JQ_VERSION}" \
        tesseract-ocr=="${TESSERACT_VERSION}" \
        tesseract-ocr-data-eng=="${TESSERACT_VERSION}" \
        tesseract-ocr-data-fra=="${TESSERACT_VERSION}" \
        tesseract-ocr-data-spa=="${TESSERACT_VERSION}" \
        tesseract-ocr-data-ita=="${TESSERACT_VERSION}" \
        tesseract-ocr-data-por=="${TESSERACT_VERSION}" \
        tesseract-ocr-data-hin=="${TESSERACT_VERSION}" \
        tesseract-ocr-data-deu=="${TESSERACT_VERSION}" \
        tesseract-ocr-data-jpn=="${TESSERACT_VERSION}" \
        tesseract-ocr-data-rus=="${TESSERACT_VERSION}" \
        poppler-utils=="${POPPLER_VERSION}"

COPY . /app

ENTRYPOINT ["/app/docker-entrypoint.sh"]
