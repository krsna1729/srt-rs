FROM debian:unstable

ARG RUST_VERSION=1.96.0

# Keep this image limited to dependencies needed by the real-libsrt interop
# suite. `linux-libc-dev` supplies the UAPI declarations used while building
# the workspace's Glommio dependency.
RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        ca-certificates \
        build-essential \
        clang \
        curl \
        git \
        linux-libc-dev \
        mold \
        pkg-config \
        srt-tools \
    && rm -rf /var/lib/apt/lists/* \
    && curl --fail --show-error --silent --location https://sh.rustup.rs \
        --output /tmp/rustup-init.sh \
    && sh /tmp/rustup-init.sh -y --profile minimal --default-toolchain "${RUST_VERSION}" \
    && rm /tmp/rustup-init.sh

ENV PATH=/root/.cargo/bin:${PATH}
# Glommio 0.9's bundled liburing header refers to `struct open_how` without
# including its Linux UAPI declaration. Debian sid exposes it here.
ENV CFLAGS="-include linux/openat2.h"

RUN rustc --version \
    && cargo --version \
    && srt-live-transmit -version \
    && srt-file-transmit -version
