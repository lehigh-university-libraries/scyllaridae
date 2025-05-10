FROM python:3.13-alpine@sha256:452682e4648deafe431ad2f2391d726d7c52f0ff291be8bd4074b10379bb89ff

RUN mkdir -p /docs

WORKDIR /docs

COPY requirements.txt .
RUN apk add --no-cache cairo \
  && pip install -r requirements.txt 

COPY . .
RUN mkdocs build

# serve the docs via nginx
FROM nginx:1.28@sha256:0ad9e58f00f6a0d92f8c0a2a32285366a0ee948d9f91aee4a2c965a5516c59d5
COPY --from=0 /docs/site /usr/share/nginx/html
