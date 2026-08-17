# syntax=docker/dockerfile:1
# ---------------------------------------------------------------------------
# UniMail — multi-stage build.
#
# Build stage uses the full Rust image (includes a C compiler, required by the
# bundled SQLite and rustls/ring). Runtime stage is a minimal Debian image.
# ---------------------------------------------------------------------------

FROM rust:1.97-bookworm AS builder

WORKDIR /app

# Cache dependencies first, then copy source.
COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --release --locked

# ---------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

# ca-certificates is required for outbound TLS to login.microsoftonline.com and
# graph.microsoft.com.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/target/release/unimail /usr/local/bin/unimail

# Persist the SQLite database outside the container image.
VOLUME ["/data"]
ENV DATABASE_PATH=/data/unimail.db \
    API_BIND_ADDR=0.0.0.0:8080

# 8080 = REST API. 80 = OAuth callback (REDIRECT_URI=http://localhost). See
# README for the loopback-callback deployment note.
EXPOSE 8080 80

ENTRYPOINT ["unimail"]
CMD ["serve"]
