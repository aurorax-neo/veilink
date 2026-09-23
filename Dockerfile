FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/veilink ./cmd/veilink \
 && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/devcert ./tools/devcert

FROM alpine:3.23
RUN apk add --no-cache ca-certificates \
 && mkdir -p /data /certs && chown -R 65532:65532 /data /certs
COPY --from=build /out/veilink /out/devcert /usr/local/bin/
USER 65532:65532
WORKDIR /data
ENTRYPOINT ["/usr/local/bin/veilink"]
CMD ["version"]
