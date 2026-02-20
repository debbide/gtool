FROM golang:1.22-alpine AS builder

WORKDIR /app

# Copy source code
COPY . .

# Build for multi-arch? No, Dockerfile usually builds for the current platform.
# We'll rely on Docker Buildx in GitHub Actions for multi-arch images.
RUN CGO_ENABLED=0 go build -ldflags "-s -w -extldflags '-static'" -o server .

FROM scratch

# Metadata
LABEL maintainer="debbide"
LABEL description="gtool - High performance tools management server"

# Copy binary from builder
COPY --from=builder /app/server /server

# Important for SSL connections (Cloudflare/API calls)
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Command to run
ENTRYPOINT ["/server"]
