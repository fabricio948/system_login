FROM golang:1.27-alpine AS builder

WORKDIR /app

# go.sum is copied once the first dependency is added.
COPY go.mod ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /bin/api ./cmd/api

FROM alpine:3.21

WORKDIR /app
COPY --from=builder /bin/api /app/api

EXPOSE 8080
CMD ["/app/api"]