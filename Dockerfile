FROM golang:1.23-alpine AS builder

WORKDIR /app

# 安装 git 和 ca-certificates，某些依赖可能需要
RUN apk add --no-cache git ca-certificates

COPY go.mod go.sum ./
RUN go mod download -x || (cat go.mod && cat go.sum && exit 1)

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o zai-proxy .

FROM alpine:latest

WORKDIR /app

# 安装 ca-certificates 以支持 HTTPS
RUN apk add --no-cache ca-certificates

COPY --from=builder /app/zai-proxy .

# proxies.txt 可通过 docker run -v ./proxies.txt:/app/proxies.txt 挂载
VOLUME ["/app/proxies.txt"]

EXPOSE 8000

CMD ["./zai-proxy"]
