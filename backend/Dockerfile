FROM golang:1.23-alpine AS builder
WORKDIR /app
COPY backend/ .
RUN go mod tidy
RUN go build -o quantum-toolkit


FROM alpine:3.18
WORKDIR /app
COPY frontend/ ./frontend
ENV GIN_MODE=release
COPY --from=builder /app/quantum-toolkit .
EXPOSE 8080
CMD ["./quantum-toolkit"]