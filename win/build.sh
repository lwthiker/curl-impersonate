#!/bin/bash

set -ex

mkdir build/
cd build/

# Download and patch boringssl

BORING_SSL_COMMIT=d24a38200fef19150eef00cad35b138936c08767
curl -L https://github.com/google/boringssl/archive/${BORING_SSL_COMMIT}.zip -o boringssl.zip
unzip -q -o boringssl.zip
mv boringssl-${BORING_SSL_COMMIT} boringssl

cd boringssl

patchfile=../../chrome/patches/boringssl-old-ciphers.patch
patch -p1 < $patchfile
sed -i 's/-ggdb//g' CMakeLists.txt
sed -i 's/-Werror//g' CMakeLists.txt

cmake -G "Ninja" -S . -B lib -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=gcc.exe -DOPENSSL_NO_ASM=1
ninja -C lib crypto ssl
mv lib/crypto/libcrypto.a lib/libcrypto.a
mv lib/ssl/libssl.a lib/libssl.a

cd ..

export ZLIB_PATH=zlib_stub
export ZSTD_PATH=zstd_stub
export BROTLI_PATH=brotli_stub
export BROTLI_LIBS='-lbrotlidec -lbrotlicommon'
export NGHTTP2_PATH=nghttp2_stub
export LIBIDN2_PATH=idn2_stub
export SSL=1
export OPENSSL_PATH=$PWD/boringssl
export OPENSSL_LIBPATH=$PWD/boringssl/lib
export OPENSSL_LIBS='-lssl -lcrypto'


CURL_VERSION=curl-8_1_1

curl -L https://github.com/curl/curl/archive/${CURL_VERSION}.zip -o curl.zip
unzip -q -o curl.zip
mv curl-${CURL_VERSION} curl

# Apparently, building curl on windows has changes since this commit:
# https://github.com/curl/curl/commit/a8861b6ccdd7ca35b6115588a578e36d765c9e38

cd curl

patchfile=../../chrome/patches/curl-impersonate.patch
patch -p1 < $patchfile

sed -i 's/-shared/-s -static -shared/g' lib/Makefile.mk
sed -i 's/-static/-s -static/g' src/Makefile.mk

sed -i 's/-DUSE_NGHTTP2/-DUSE_NGHTTP2 -DNGHTTP2_STATICLIB/g' lib/Makefile.mk
sed -i 's/-DUSE_NGHTTP2/-DUSE_NGHTTP2 -DNGHTTP2_STATICLIB/g' src/Makefile.mk

sed -i 's/-lidn2/-lidn2 -lunistring -liconv/g' lib/Makefile.mk
sed -i 's/-lidn2/-lidn2 -lunistring -liconv/g' src/Makefile.mk

mingw32-make -f Makefile.dist mingw32-clean
mingw32-make -f Makefile.dist mingw32 -j CFLAGS="-DUSE_HTTP2=1 -DUSE_WEBSOCKETS=1 -DUSE_ECH=1 -Wno-unused-variable" CFG=-ssl-zlib-nghttp2-idn2-brotli-zstd-ipv6

mkdir -p ../dist
mv lib/libcurl* ../dist/
mv src/*.exe ../dist/

cd ..
dist/curl -V
