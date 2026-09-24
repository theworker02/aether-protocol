FROM rust:1.81-bookworm AS builder
WORKDIR /src
COPY Cargo.toml ./
COPY crates ./crates
RUN cargo build --release -p aether-node -p aether-cli

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/target/release/aether-node /usr/local/bin/aether-node
COPY --from=builder /src/target/release/aether /usr/local/bin/aether
EXPOSE 8545
ENTRYPOINT ["aether-node"]
