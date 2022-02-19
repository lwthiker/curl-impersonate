# Python is needed for building libnss
FROM python:3.10.1-slim-buster

WORKDIR /build

# Dependencies for building libnss
# See https://firefox-source-docs.mozilla.org/security/nss/build.html#mozilla-projects-nss-building
RUN apt-get update && \
    apt-get install -y mercurial git ninja-build python3-pip curl zlib1g-dev libbrotli-dev

# Also needed for building libnss
RUN pip install gyp-next

ARG NSS_VERSION=nss-3.74
# This tarball is already bundled with nspr, a dependency of libnss.
ARG NSS_URL=https://ftp.mozilla.org/pub/security/nss/releases/NSS_3_74_RTM/src/nss-3.74-with-nspr-4.32.tar.gz

# Download the nss library.
RUN curl -o ${NSS_VERSION}.tar.gz ${NSS_URL}
RUN tar xf ${NSS_VERSION}.tar.gz && \
    cd ${NSS_VERSION}/nss && \
    ./build.sh -o --disable-tests --static

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

# Patch Curl.
COPY patches/curl-*.patch ${CURL_VERSION}/

# Re-generate the configure script
RUN cd ${CURL_VERSION} && \
    for p in $(ls curl-*.patch); do patch -p1 < $p; done && \
    autoreconf -fi

# Compile curl with nss
RUN cd ${CURL_VERSION} && \
    ./configure --with-nss=/build/${NSS_VERSION}/dist/Release --enable-static --disable-shared CFLAGS="-I/build/${NSS_VERSION}/dist/public/nss -I/build/${NSS_VERSION}/dist/Release/include/nspr" --with-nghttp2=/usr/local && \
    make

# curl tries to load the CA certificates for libnss.
# It loads them from /usr/lib/x86_64-linux-gnu/nss/libnssckbi.so,
# which is supplied by libnss3 on Debian/Ubuntu
RUN apt-get install -y libnss3

# 'xxd' is needed for the wrapper curl_ff95 script
RUN apt-get install -y xxd

RUN mkdir out && \
    cp ${CURL_VERSION}/src/curl out/curl-impersonate

# Wrapper script
COPY curl_* out/

RUN chmod +x out/*
