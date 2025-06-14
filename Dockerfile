FROM golang:1.23-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -o tgmg -ldflags="-s -w" .

FROM alpine:3.21.3

RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/tgmg .

ENTRYPOINT ["./tgmg"]
