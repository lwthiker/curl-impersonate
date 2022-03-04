FROM python:3.10.1-slim-buster

WORKDIR /tests

RUN apt-get update && \
    apt-get install -y tcpdump libbrotli1 libnss3 gcc libcurl4-openssl-dev nghttp2-server

COPY requirements.txt requirements.txt

RUN pip install --upgrade pip && \
    pip install -r requirements.txt

RUN mkdir /tests/firefox /tests/chrome

# Copy the built binaries from both containers
COPY --from=curl-impersonate-ff /build/out/* /tests/firefox/
COPY --from=curl-impersonate-chrome /build/out/* /tests/chrome/

COPY . .

# Compile 'minicurl' which is used for testing libcurl-impersonate.
# 'minicurl' is compiled against the "regular" libcurl.
# libcurl-impersonate will replace it at runtime via LD_PRELOAD.
RUN gcc -Wall -Werror -o minicurl minicurl.c `curl-config --libs`

ENTRYPOINT ["pytest"]
