# Getting started with curl-impersonate

curl-impersonate can be run on Linux and macOS. Partial support for Windows is currently available through a different project: [curl-impersonate-win](https://github.com/depler/curl-impersonate-win).

## Installation
Installation instructions are available on the [main page](https://github.com/lwthiker/curl-impersonate#installation)

The project supplies two modified flavors of curl:
* The *Chrome version* is a modified curl binary and libcurl library that can impersonate Chrome, Edge and Safari. It uses BoringSSL, Chrome's TLS library. It is based on a patched curl version with added support for some additional TLS extensions and modified HTTP/2 settings that make it look like a browser.
* The *Firefox version* is a modified curl binary that can impersonate Firefox. It uses NSS, Mozilla's TLS library which is used by Firefox.
