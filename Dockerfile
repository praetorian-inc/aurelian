# Start with the official Go image
FROM golang:1.22-bullseye AS builder

# Set the working directory in the container
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy the source code
COPY . .

# Build the application with optimizations
RUN CGO_ENABLED=0 GOOS=linux go build -v -ldflags="-s -w" -o main main.go

# Create a minimal production image
FROM alpine:latest

# Add CA certificates for HTTPS
RUN apk --no-cache add ca-certificates

WORKDIR /root/

# Copy the binary from builder
COPY --from=builder /app/main ./nebula

# Use ENTRYPOINT to specify the binary
ENTRYPOINT ["./nebula"]

# Use CMD to specify default arguments that can be overridden
CMD []