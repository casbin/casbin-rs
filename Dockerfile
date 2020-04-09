FROM rust:1.40-stretch

# Dependancies.
RUN apt-get update --fix-missing \
    && apt-get install -y \
        cmake \
        libssl-dev \
        pkg-config \
        zlib1g-dev

# Nightly toolchain
RUN rustup toolchain install stable

# Copy source.
WORKDIR /usr/src/casbin-rs
COPY . .
