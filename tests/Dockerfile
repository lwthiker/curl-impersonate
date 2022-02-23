FROM python:3.10.1-slim-buster

WORKDIR /tests

RUN apt-get update && \
    apt-get install -y tcpdump libbrotli1 libnss3

COPY requirements.txt requirements.txt

RUN pip install --upgrade pip && \
    pip install -r requirements.txt

RUN mkdir /tests/firefox /tests/chrome

# Copy the built binaries from both containers
COPY --from=curl-impersonate-ff /build/out/* /tests/firefox/
COPY --from=curl-impersonate-chrome /build/out/* /tests/chrome/

COPY . .

ENTRYPOINT ["pytest"]
