# syntax=docker/dockerfile:1

FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /ppe ./cmd/ppe

FROM alpine:3.20
RUN apk add --no-cache ca-certificates \
 && adduser -D -H -u 10001 ppe \
 && mkdir -p /data \
 && chown ppe:ppe /data
COPY --from=build /ppe /ppe
USER ppe
WORKDIR /data
ENV TMPDIR=/tmp
EXPOSE 8080
ENTRYPOINT ["/ppe"]
CMD ["serve"]
