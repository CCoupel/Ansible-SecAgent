# Build stage
FROM golang:1.25-alpine AS builder

WORKDIR /build

# Install build dependencies
RUN apk add --no-cache git make gcc musl-dev

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the binary — CGO required by go-sqlite3
RUN CGO_ENABLED=1 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-s -w" -o secagent-server ./cmd/server

# Runtime stage
FROM alpine:3.18

WORKDIR /app

# Install runtime dependencies
RUN apk add --no-cache ca-certificates sqlite-libs

# Copy binary from builder
COPY --from=builder /build/secagent-server /app/secagent-server

# Create non-root user
RUN addgroup -S relay && adduser -S relay -G relay
USER relay

# Health check
HEALTHCHECK --interval=10s --timeout=5s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:7770/health || exit 1

# Expose ports
# 7770 - API endpoints (register, exec, upload, fetch, inventory)
# 7771 - Admin endpoints (authorize, revoke, minions)
# 7772 - WebSocket agent connections
EXPOSE 7770 7771 7772

# Run server
CMD ["/app/secagent-server"]
