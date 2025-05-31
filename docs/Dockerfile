FROM python:3.13-alpine@sha256:a94caf6aab428e086bc398beaf64a6b7a0fad4589573462f52362fd760e64cc9

RUN mkdir -p /docs

WORKDIR /docs

COPY requirements.txt .
RUN apk add --no-cache cairo \
  && pip install -r requirements.txt 

COPY . .
RUN mkdocs build

# serve the docs via nginx
FROM nginx:1.28@sha256:eaa7e36decc3421fc04478c586dfea0d931cebe47d5bc0b15d758a32ba51126f
COPY --from=0 /docs/site /usr/share/nginx/html
