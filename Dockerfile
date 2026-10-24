# syntax=docker/dockerfile:1

FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /piplyzer ./cmd/ppe

FROM alpine:3.20
RUN apk add --no-cache ca-certificates \
 && adduser -D -H -u 10001 piplyzer \
 && mkdir -p /data \
 && chown piplyzer:piplyzer /data
COPY --from=build /piplyzer /piplyzer
USER piplyzer
WORKDIR /data
ENV TMPDIR=/tmp
EXPOSE 8080
ENTRYPOINT ["/piplyzer"]
CMD ["serve"]
