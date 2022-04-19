ARG FIREFOX_IMAGE=curl-impersonate-ff
ARG CHROME_IMAGE=curl-impersonate-chrome

FROM ${FIREFOX_IMAGE} as ff
FROM ${CHROME_IMAGE} as chrome

FROM python:3.10.1-slim-buster

WORKDIR /tests

RUN apt-get update && \
    apt-get install -y tcpdump libbrotli1 libnss3 gcc libcurl4-openssl-dev nghttp2-server

COPY requirements.txt requirements.txt

RUN pip install --upgrade pip && \
    pip install -r requirements.txt

RUN mkdir /tests/firefox /tests/chrome

# Copy the built binaries from both containers
COPY --from=ff /build/out/curl-impersonate-ff /tests/install/bin/
COPY --from=ff /build/out/curl_* /tests/install/bin/
COPY --from=ff /build/out/libcurl-impersonate* /tests/install/lib/
COPY --from=chrome /build/out/curl-impersonate-chrome /tests/install/bin/
COPY --from=chrome /build/out/curl_* /tests/install/bin/
COPY --from=chrome /build/out/libcurl-impersonate* /tests/install/lib/

COPY . .

# Compile 'minicurl' which is used for testing libcurl-impersonate.
# 'minicurl' is compiled against the "regular" libcurl.
# libcurl-impersonate will replace it at runtime via LD_PRELOAD.
RUN gcc -Wall -Werror -o /tests/install/bin/minicurl minicurl.c `curl-config --libs`

ENTRYPOINT ["pytest", "--install-dir", "/tests/install"]
