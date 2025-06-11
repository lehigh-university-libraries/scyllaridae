FROM python:3.13-alpine@sha256:b4d299311845147e7e47c970566906caf8378a1f04e5d3de65b5f2e834f8e3bf

RUN mkdir -p /docs

WORKDIR /docs

COPY requirements.txt .
RUN apk add --no-cache cairo \
  && pip install -r requirements.txt 

COPY . .
RUN mkdocs build

# serve the docs via nginx
FROM nginx:1.28@sha256:20555a07052bb7a1a0ed233d5dba2bdafb75e537948fadbc0e1fef151088dcdd
COPY --from=0 /docs/site /usr/share/nginx/html
