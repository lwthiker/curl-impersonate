# Use same base as the existing Dockerfile
FROM python:3.10.1-slim-buster

WORKDIR /build

# Dependencies for downloading and building BoringSSL
RUN apt-get update && \
    apt-get install -y git g++ cmake golang-go ninja-build curl unzip zlib1g-dev libbrotli-dev

# BoringSSL doesn't have versions. Choose a commit that is used in a stable
# Chromium version.
ARG BORING_SSL_COMMIT=3a667d10e94186fd503966f5638e134fe9fb4080
RUN curl -L https://github.com/google/boringssl/archive/${BORING_SSL_COMMIT}.zip -o boringssl.zip && \
    unzip boringssl && \
    mv boringssl-${BORING_SSL_COMMIT} boringssl

# Compile BoringSSL.
# See https://boringssl.googlesource.com/boringssl/+/HEAD/BUILDING.md
COPY patches/boringssl-*.patch boringssl/
RUN cd boringssl && \
    for p in $(ls boringssl-*.patch); do patch -p1 < $p; done && \
    mkdir build && cd build && \
    cmake -DCMAKE_POSITION_INDEPENDENT_CODE=on -GNinja .. && \
    ninja

# Fix the directory structure so that curl can compile against it.
# See https://everything.curl.dev/source/build/tls/boringssl 
RUN mkdir boringssl/build/lib && \
    ln -s ../crypto/libcrypto.a boringssl/build/lib/libcrypto.a && \
    ln -s ../ssl/libssl.a boringssl/build/lib/libssl.a && \
    cp -R boringssl/include boringssl/build

ARG NGHTTP2_VERSION=nghttp2-1.46.0
ARG NGHTTP2_URL=https://github.com/nghttp2/nghttp2/releases/download/v1.46.0/nghttp2-1.46.0.tar.bz2

# The following are needed because we are going to change some autoconf scripts,
# both for libnghttp2 and curl.
RUN apt-get install -y autoconf automake autotools-dev pkg-config libtool

# Download nghttp2 for HTTP/2.0 support.
RUN curl -o ${NGHTTP2_VERSION}.tar.bz2 -L ${NGHTTP2_URL}
RUN tar xf ${NGHTTP2_VERSION}.tar.bz2

# Patch nghttp2 pkg config file to support static builds.
COPY patches/libnghttp2-*.patch ${NGHTTP2_VERSION}/
RUN cd ${NGHTTP2_VERSION} && \
    for p in $(ls libnghttp2-*.patch); do patch -p1 < $p; done && \
    autoreconf -i && automake && autoconf

# Compile nghttp2
RUN cd ${NGHTTP2_VERSION} && \
    ./configure && \
    make && make install

# Download curl.
ARG CURL_VERSION=curl-7.81.0
RUN curl -o ${CURL_VERSION}.tar.xz https://curl.se/download/${CURL_VERSION}.tar.xz
RUN tar xf ${CURL_VERSION}.tar.xz

# Patch curl and re-generate the configure script
COPY patches/curl-*.patch ${CURL_VERSION}/
RUN cd ${CURL_VERSION} && \
    for p in $(ls curl-*.patch); do patch -p1 < $p; done && \
    autoreconf -fi

# Compile curl with BoringSSL & nghttp2.
# Enable keylogfile for debugging of TLS traffic.
RUN cd ${CURL_VERSION} && \
    ./configure --with-openssl=/build/boringssl/build --enable-static --disable-shared --with-nghttp2=/usr/local LIBS="-pthread" CFLAGS="-I/build/boringssl/build" USE_CURL_SSLKEYLOGFILE=true && \
    make

# 'xxd' is needed for the wrapper script
RUN apt-get install -y xxd

RUN mkdir out && \
    cp ${CURL_VERSION}/src/curl out/curl-impersonate

# Wrapper script
COPY curl_chrome* curl_edge* out/

RUN chmod +x out/*
