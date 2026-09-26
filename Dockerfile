ARG NPM_REGISTRY=https://registry.npmmirror.com
ARG GOPROXY=https://goproxy.cn,direct
ARG APK_MIRROR=https://mirrors.ustc.edu.cn/alpine

FROM golang:alpine AS build
WORKDIR /src
ARG GOPROXY
ARG VERSION=dev
ARG COMMIT=unknown
ENV GOPROXY=${GOPROXY}
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X veilink/internal/buildinfo.Version=${VERSION} -X veilink/internal/buildinfo.Commit=${COMMIT}" -o /out/veilink ./cmd/veilink

FROM node:alpine AS ui
WORKDIR /src/frontend
ARG NPM_REGISTRY
RUN npm config set registry ${NPM_REGISTRY}
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

# One release image; the required subcommand selects the runtime role.
FROM alpine:3.23
ARG APK_MIRROR
RUN printf '%s/v3.23/main\n%s/v3.23/community\n' "$APK_MIRROR" "$APK_MIRROR" > /etc/apk/repositories \
 && apk add --no-cache ca-certificates tzdata curl sqlite \
 && mkdir -p /data \
 && chown 65532:65532 /data
COPY --from=build /out/veilink /usr/local/bin/veilink
COPY --from=ui /src/html /usr/local/html
COPY docker-healthcheck.sh /usr/local/bin/docker-healthcheck.sh
RUN chmod 755 /usr/local/bin/docker-healthcheck.sh
WORKDIR /data
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/veilink"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ["/usr/local/bin/docker-healthcheck.sh"]
