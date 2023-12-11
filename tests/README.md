The tests verify that `curl-impersonate` has the same network signature as that of the supported browsers. They do not test curl's functionality itself.

## Running the tests

The tests assume that you've built both `curl-impersonate-chrome` and `curl-impersonate-ff` docker images before (see [Building from source](https://github.com/lwthiker/curl-impersonate#building-from-source)).

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
For each supported browser, the following tests are performed:
* A packet capture is started while `curl-impersonate` is run with the relevant wrapper script. The Client Hello message is extracted from the capture and compared against the known signature of the browser.
* `curl-impersonate` is run, connecting to a local `nghttpd` server (a simple HTTP/2 server). The HTTP/2 pseudo-headers and headers are extracted from the output log of `nghttpd` and compared to the known headers of the browser.

## What's missing
The following tests are still missing:
- [ ] Test that `curl-impersonate` sends the same HTTP/2 SETTINGS as the browser.
- [ ] Capture traffic automatically from different browsers
- [x] Update safari versions, double `rsa_pss_rsae_sha384`

