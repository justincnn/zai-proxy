FROM golang:1.23-alpine AS builder

WORKDIR /app

# 设置 Go 代理以加速依赖下载（针对国内网络）
ENV GOPROXY=https://goproxy.cn,direct

COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o zai-proxy .

FROM alpine:latest

WORKDIR /app

COPY --from=builder /app/zai-proxy .

# proxies.txt 可通过 docker run -v ./proxies.txt:/app/proxies.txt 挂载
VOLUME ["/app/proxies.txt"]

EXPOSE 8000

CMD ["./zai-proxy"]
