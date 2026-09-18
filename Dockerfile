# syntax=docker/dockerfile:1.7
# Build stage: compile Rust binary with musl for a tiny static binary
FROM rust:1.82-alpine AS builder
WORKDIR /build

# Pre-cache deps for fast incremental rebuilds
COPY Cargo.toml Cargo.lock* ./
RUN mkdir -p src && echo 'fn main() {}' > src/main.rs && \
    cargo build --release --target x86_64-unknown-linux-musl --locked && \
    rm -rf src target/x86_64-unknown-linux-musl/release/deps/ionos-subdomain-updater*

# Now copy real source and rebuild
COPY src ./src
RUN touch src/main.rs && cargo build --release --target x86_64-unknown-linux-musl

# Runtime stage: scratch with just the static binary + CA bundle
FROM scratch

LABEL org.opencontainers.image.source="local-build"
LABEL org.opencontainers.image.title="ionos-subdomain-updater"
LABEL org.opencontainers.image.description="Rust updater that auto-creates IONOS DynDNS subdomains from a JSON config"

# CA certificates for HTTPS to api.hosting.ionos.com
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# The static binary
COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/ionos-subdomain-updater /ionos-subdomain-updater

# Tiny /etc/passwd entry for non-root UID 65534 (nobody)
COPY --from=builder /etc/passwd /etc/passwd

USER 65534:65534

# /data is where config.json + state.json live (mounted as a volume)
WORKDIR /data
ENV IONOS_UPDATER_CONFIG=/data/config.json
ENV RUST_LOG=info

EXPOSE 8080

ENTRYPOINT ["/ionos-subdomain-updater"]
