FROM golang:1.20-alpine AS builder
WORKDIR /app
COPY go.mod .
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o quantum-toolkit

FROM alpine:3.18
WORKDIR /app
COPY --from=builder /app/quantum-toolkit .
EXPOSE 8080
CMD ["./quantum-toolkit"]