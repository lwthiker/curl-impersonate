ARG CHROME_IMAGE=curl-impersonate-chrome

FROM ${CHROME_IMAGE} as chrome

FROM python:3.11-slim-bookworm

WORKDIR /tests

RUN apt-get update && \
    apt-get install -y tcpdump libbrotli1 gcc libcurl4-openssl-dev nghttp2-server git

COPY requirements.txt requirements.txt

RUN pip install --upgrade pip && \
    pip install -r requirements.txt

# Copy the built binaries from both containers
COPY --from=chrome /usr/local/ /usr/local/

# Needed to update the loader's cache
RUN ldconfig

COPY . .

# Compile 'minicurl' which is used for testing libcurl-impersonate.
# 'minicurl' is compiled against the "regular" libcurl.
# libcurl-impersonate will replace it at runtime via LD_PRELOAD.
RUN gcc -Wall -Werror -o minicurl minicurl.c `curl-config --libs`
RUN install minicurl /usr/local/bin

ENTRYPOINT ["pytest"]
