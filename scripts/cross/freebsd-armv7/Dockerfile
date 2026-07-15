FROM rust:1.97-slim-bullseye AS ufs-extractor

COPY ufs-extract /source
RUN cargo build --locked --release --manifest-path /source/Cargo.toml

FROM ghcr.io/cross-rs/aarch64-unknown-freebsd:main AS sysroot

ARG FREEBSD_IMAGE=FreeBSD-14.3-RELEASE-arm-armv7-GENERICSD.img
ARG FREEBSD_IMAGE_SHA256=b3627a92f8f8cc4b4eb0caaafe809fe0a2139a41cbaa8bee2a3c451ad81c4048
ARG FREEBSD_UFS_OFFSET=53542912

COPY --from=ufs-extractor /source/target/release/ufs-extract /usr/local/bin/ufs-extract

# FreeBSD publishes ARMv7 releases as UFS disk images rather than base.txz.
# Verify the official image and extract only the headers and runtime objects
# needed for a compiler sysroot. The offset is MBR slice 2 plus the UFS start.
RUN set -eux; \
    curl -4 --retry 5 -fsSL \
      "https://download.freebsd.org/releases/arm/armv7/ISO-IMAGES/14.3/${FREEBSD_IMAGE}.xz" \
      -o "/tmp/${FREEBSD_IMAGE}.xz"; \
    echo "${FREEBSD_IMAGE_SHA256}  /tmp/${FREEBSD_IMAGE}.xz" | sha256sum -c -; \
    xz -d "/tmp/${FREEBSD_IMAGE}.xz"; \
    ufs-extract "/tmp/${FREEBSD_IMAGE}" "${FREEBSD_UFS_OFFSET}" /opt/freebsd-armv7 \
      /usr/include \
      /lib \
      /usr/lib/Scrt1.o \
      /usr/lib/crt1.o \
      /usr/lib/crtbegin.o \
      /usr/lib/crtbeginS.o \
      /usr/lib/crtbeginT.o \
      /usr/lib/crtend.o \
      /usr/lib/crtendS.o \
      /usr/lib/crti.o \
      /usr/lib/crtn.o \
      /usr/lib/libc++.a \
      /usr/lib/libc++.so \
      /usr/lib/libc.a \
      /usr/lib/libc.so \
      /usr/lib/libc_nonshared.a \
      /usr/lib/libcompiler_rt.a \
      /usr/lib/libcxxrt.a \
      /usr/lib/libcxxrt.so \
      /usr/lib/libexecinfo.so \
      /usr/lib/libexecinfo.so.1 \
      /usr/lib/libgcc.a \
      /usr/lib/libgcc_eh.a \
      /usr/lib/libgcc_s.so \
      /usr/lib/libkvm.a \
      /usr/lib/libm.a \
      /usr/lib/libm.so \
      /usr/lib/libmemstat.a \
      /usr/lib/libmemstat.so.3 \
      /usr/lib/libprocstat.so \
      /usr/lib/libprocstat.so.1 \
      /usr/lib/libpthread.so \
      /usr/lib/librt.so \
      /usr/lib/libssp_nonshared.a \
      /usr/lib/libthr.so \
      /usr/lib/libutil.a \
      /usr/lib/libutil.so; \
    rm -f "/tmp/${FREEBSD_IMAGE}"

FROM ghcr.io/cross-rs/aarch64-unknown-freebsd:main

RUN set -eux; \
    apt-get update; \
    apt-get install --assume-yes --no-install-recommends clang lld llvm; \
    rm -rf /var/lib/apt/lists/*

COPY --from=sysroot /opt/freebsd-armv7 /opt/freebsd-armv7
COPY armv7-unknown-freebsd14-clang /usr/local/bin/
COPY armv7-unknown-freebsd14-clang++ /usr/local/bin/

RUN set -eux; \
    chmod +x \
      /usr/local/bin/armv7-unknown-freebsd14-clang \
      /usr/local/bin/armv7-unknown-freebsd14-clang++; \
    ln -s armv7-unknown-freebsd14-clang /usr/local/bin/armv7-unknown-freebsd14-gcc; \
    ln -s armv7-unknown-freebsd14-clang++ /usr/local/bin/armv7-unknown-freebsd14-g++; \
    ln -s /usr/bin/llvm-ar /usr/local/bin/armv7-unknown-freebsd14-ar; \
    ln -s /usr/bin/ld.lld /usr/local/bin/armv7-unknown-freebsd14-ld; \
    ln -s /usr/bin/llvm-nm /usr/local/bin/armv7-unknown-freebsd14-nm; \
    ln -s /usr/bin/llvm-objcopy /usr/local/bin/armv7-unknown-freebsd14-objcopy; \
    ln -s /usr/bin/llvm-objdump /usr/local/bin/armv7-unknown-freebsd14-objdump; \
    ln -s /usr/bin/llvm-ranlib /usr/local/bin/armv7-unknown-freebsd14-ranlib; \
    ln -s /usr/bin/llvm-strip /usr/local/bin/armv7-unknown-freebsd14-strip; \
    ln -s ../../lib/libdevstat.so.7 /opt/freebsd-armv7/usr/lib/libdevstat.so; \
    ln -s ../../lib/libkvm.so.7 /opt/freebsd-armv7/usr/lib/libkvm.so; \
    ln -s libmemstat.so.3 /opt/freebsd-armv7/usr/lib/libmemstat.so; \
    printf 'int main(void) { return 0; }\n' | \
      armv7-unknown-freebsd14-clang -x c - -o /tmp/freebsd-armv7-smoke; \
    readelf -h /tmp/freebsd-armv7-smoke | grep -q 'Machine:.*ARM'; \
    rm /tmp/freebsd-armv7-smoke

ENV CROSS_TOOLCHAIN_PREFIX=armv7-unknown-freebsd14- \
    CROSS_SYSROOT=/opt/freebsd-armv7 \
    CARGO_TARGET_ARMV7_UNKNOWN_FREEBSD_LINKER=armv7-unknown-freebsd14-clang \
    AR_armv7_unknown_freebsd=armv7-unknown-freebsd14-ar \
    CC_armv7_unknown_freebsd=armv7-unknown-freebsd14-clang \
    CXX_armv7_unknown_freebsd=armv7-unknown-freebsd14-clang++ \
    CMAKE_TOOLCHAIN_FILE_armv7_unknown_freebsd=/opt/toolchain.cmake \
    BINDGEN_EXTRA_CLANG_ARGS_armv7_unknown_freebsd="--target=armv7-unknown-freebsd14.3-gnueabihf --sysroot=/opt/freebsd-armv7" \
    ARMV7_UNKNOWN_FREEBSD_OPENSSL_DIR=/opt/freebsd-armv7 \
    CROSS_CMAKE_SYSTEM_NAME=FreeBSD \
    CROSS_CMAKE_SYSTEM_PROCESSOR=armv7 \
    CROSS_CMAKE_CRT=freebsd \
    CROSS_CMAKE_OBJECT_FLAGS="-ffunction-sections -fdata-sections -fPIC -mfloat-abi=hard"
