#
# NOTE: THIS DOCKERFILE IS GENERATED FROM "Dockerfile.template" VIA
# "generate-dockerfiles.sh".
#
# PLEASE DO NOT EDIT IT DIRECTLY.
#

# Python is needed for building libnss.
# Use it as a common base.
FROM python:3.10.1-slim-buster

WORKDIR /build

# Common dependencies
RUN apt-get update && \
    apt-get install -y git ninja-build cmake curl zlib1g-dev

# The following are needed because we are going to change some autoconf scripts,
# both for libnghttp2 and curl.
RUN apt-get install -y autoconf automake autotools-dev pkg-config libtool

# Dependencies for building libnss
# See https://firefox-source-docs.mozilla.org/security/nss/build.html#mozilla-projects-nss-building
RUN apt-get install -y mercurial python3-pip

# curl tries to load the CA certificates for libnss.
# It loads them from /usr/lib/x86_64-linux-gnu/nss/libnssckbi.so,
# which is supplied by libnss3 on Debian/Ubuntu
RUN apt-get install -y libnss3

# Download and compile libbrotli
ARG BROTLI_VERSION=1.0.9
RUN curl -L https://github.com/google/brotli/archive/refs/tags/v${BROTLI_VERSION}.tar.gz -o brotli-${BROTLI_VERSION}.tar.gz && \
    tar xf brotli-${BROTLI_VERSION}.tar.gz
RUN cd brotli-${BROTLI_VERSION} && \
    mkdir build && cd build && \
    cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=./installed .. && \
    cmake --build . --config Release --target install

# Needed for building libnss
RUN pip install gyp-next

ARG NSS_VERSION=nss-3.75
# This tarball is already bundled with nspr, a dependency of libnss.
ARG NSS_URL=https://ftp.mozilla.org/pub/security/nss/releases/NSS_3_75_RTM/src/nss-3.75-with-nspr-4.32.tar.gz

# Download and compile nss.
RUN curl -o ${NSS_VERSION}.tar.gz ${NSS_URL}
RUN tar xf ${NSS_VERSION}.tar.gz && \
    cd ${NSS_VERSION}/nss && \
    ./build.sh -o --disable-tests --static

ARG NGHTTP2_VERSION=nghttp2-1.46.0
ARG NGHTTP2_URL=https://github.com/nghttp2/nghttp2/releases/download/v1.46.0/nghttp2-1.46.0.tar.bz2

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
    ./configure --with-pic && \
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

# Compile curl with nghttp2, libbrotli and nss (firefox) or boringssl (chrome).
# Enable keylogfile for debugging of TLS traffic.
RUN cd ${CURL_VERSION} && \
    ./configure --prefix=/build/install \
                --enable-static \
                --disable-shared \
                --with-nghttp2=/usr/local \
                --with-brotli=/build/brotli-${BROTLI_VERSION}/build/installed \
                --with-nss=/build/${NSS_VERSION}/dist/Release \
                CFLAGS="-I/build/${NSS_VERSION}/dist/public/nss -I/build/${NSS_VERSION}/dist/Release/include/nspr" \
                USE_CURL_SSLKEYLOGFILE=true && \
    make && make install

RUN mkdir out && \
    cp /build/install/bin/curl-impersonate-ff out/ && \
    ln -s curl-impersonate-ff out/curl-impersonate && \
    strip out/curl-impersonate

RUN rm -Rf /build/install

# Re-compile libcurl dynamically
RUN cd ${CURL_VERSION} && \
    ./configure --prefix=/build/install \
                --with-nghttp2=/usr/local \
                --with-brotli=/build/brotli-${BROTLI_VERSION}/build/installed \
                --with-nss=/build/${NSS_VERSION}/dist/Release \
                CFLAGS="-I/build/${NSS_VERSION}/dist/public/nss -I/build/${NSS_VERSION}/dist/Release/include/nspr" \
                USE_CURL_SSLKEYLOGFILE=true && \
    make clean && make && make install

# Copy libcurl-impersonate and symbolic links
RUN cp -d /build/install/lib/libcurl-impersonate* /build/out

RUN ver=$(readlink -f curl-7.81.0/lib/.libs/libcurl-impersonate-ff.so | sed 's/.*so\.//') && \
    major=$(echo -n $ver | cut -d'.' -f1) && \
    ln -s "libcurl-impersonate-ff.so.$ver" "out/libcurl-impersonate.so.$ver" && \
    ln -s "libcurl-impersonate.so.$ver" "out/libcurl-impersonate.so" && \
    strip "out/libcurl-impersonate.so.$ver"

# Wrapper scripts
COPY curl_ff* out/
RUN chmod +x out/curl_*
