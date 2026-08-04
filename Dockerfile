FROM rust:1.97-slim-bookworm AS build
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY migrations ./migrations
COPY src ./src
RUN cargo build --release --locked

FROM debian:bookworm-slim
LABEL org.opencontainers.image.source=https://github.com/ponzu07/ponpilot-api
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates wget \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /build/target/release/ponpilot-api /usr/local/bin/
RUN install -d -o 65534 -g 65534 /data
VOLUME /data
USER 65534:65534
ENV BIND=0.0.0.0:8080
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/ponpilot-api"]
