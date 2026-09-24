ARG NPM_REGISTRY=https://registry.npmmirror.com
ARG GOPROXY=https://goproxy.cn,direct

FROM node:alpine AS ui
WORKDIR /src/frontend
ARG NPM_REGISTRY
RUN npm config set registry ${NPM_REGISTRY}
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM golang:alpine AS build
WORKDIR /src
ARG GOPROXY
ENV GOPROXY=${GOPROXY}
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/veilink ./cmd/veilink \
 && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/devcert ./tools/devcert

FROM alpine:3.23
RUN apk add --no-cache ca-certificates curl tzdata \
 && mkdir -p /data /certs && chown -R 65532:65532 /data /certs
COPY --from=build /out/veilink /out/devcert /usr/local/bin/
COPY --from=ui /src/html /usr/local/html
COPY --chmod=755 docker-healthcheck.sh /usr/local/bin/docker-healthcheck.sh
USER 65532:65532
WORKDIR /data
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ["/usr/local/bin/docker-healthcheck.sh"]
ENTRYPOINT ["/usr/local/bin/veilink"]
CMD ["version"]
