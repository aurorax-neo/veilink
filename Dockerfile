ARG NPM_REGISTRY=https://registry.npmmirror.com
ARG GOPROXY=https://goproxy.cn,direct

FROM golang:alpine AS build
WORKDIR /src
ARG GOPROXY
ENV GOPROXY=${GOPROXY}
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/veilink ./cmd/veilink

# Each published target contains only its role's runtime resources. The Go
# executable is common, but no node image contains the Master Web UI or curl.
FROM alpine:3.23 AS runtime
RUN apk add --no-cache ca-certificates tzdata \
 && mkdir -p /data \
 && chown 65532:65532 /data
COPY --from=build /out/veilink /usr/local/bin/veilink
WORKDIR /data

FROM runtime AS server
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/veilink", "server"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ["kill", "-0", "1"]

FROM runtime AS client
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/veilink", "client"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ["kill", "-0", "1"]

# Build the frontend only for the Master release target.
FROM node:alpine AS ui
WORKDIR /src/frontend
ARG NPM_REGISTRY
RUN npm config set registry ${NPM_REGISTRY}
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM runtime AS master
USER root
RUN apk add --no-cache curl sqlite
COPY --from=ui /src/html /usr/local/html
COPY docker-healthcheck.sh /usr/local/bin/docker-healthcheck.sh
RUN chmod 755 /usr/local/bin/docker-healthcheck.sh
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/veilink", "master"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ["/usr/local/bin/docker-healthcheck.sh"]
