FROM debian:unstable

ARG RUST_VERSION=1.96.0

# Keep this image limited to dependencies needed by the real-libsrt interop
# suite. Debian's packaged libsrt leaves bonding disabled, so build the same
# current sid source with that one additional feature for the group test.
# `linux-libc-dev` supplies the UAPI declarations used while building the
# workspace's Glommio dependency.
RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        ca-certificates \
        build-essential \
        clang \
        cmake \
        curl \
        dpkg-dev \
        git \
        libssl-dev \
        linux-libc-dev \
        mold \
        ninja-build \
        pkg-config \
    && printf '%s\n' 'deb-src http://deb.debian.org/debian sid main' > /etc/apt/sources.list.d/sid-src.list \
    && apt-get update \
    && cd /tmp \
    && apt-get source srt \
    && source_dir="$(find /tmp -maxdepth 1 -type d -name 'srt-*' -print -quit)" \
    && test -n "$source_dir" \
    && cmake -S "$source_dir" -B /tmp/srt-build -G Ninja \
        -DCMAKE_BUILD_TYPE=Release \
        -DENABLE_BONDING=ON \
        -DENABLE_TESTING=OFF \
        -DUSE_ENCLIB=openssl-evp \
    && cmake --build /tmp/srt-build \
    && cmake --install /tmp/srt-build \
    && ldconfig \
    && rm -rf /tmp/srt-* /var/lib/apt/lists/* \
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
