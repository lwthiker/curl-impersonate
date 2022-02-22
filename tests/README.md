The tests verify that `curl-impersonate` has the same network signature as that of the supported browsers. They do not test curl's functionality itself.

## Running the tests

The tests assume that you've built both `curl-impersonate-chrome` and `curl-impersonate-ff` docker images before (see [Installation](https://github.com/lwthiker/curl-impersonate#installation)).

To run the tests, build with:
```
docker build -t curl-impersonate-tests tests/
```
then run with:
```
docker run --rm curl-impersonate-tests
```
This simply runs `pytest` in the container. You can pass additional flags to `pytest` such as `--log-cli-level DEBUG`.

## How the tests work
For each supported browser, a packet capture is started while `curl-impersonate` is run with the relevant wrapper script. The Client Hello message is extracted from the capture, and compared against the known signature of the browser.

## What's missing
The following tests are still missing:
* Test that `curl-impersonate` sends the HTTP headers in the same order as the browser.
* Test that `curl-impersonate` sends the HTTP/2 pseudo-headers in the same order as the browser.
* Test that `curl-impersonate` sends the same HTTP/2 SETTINGS as the browser.
