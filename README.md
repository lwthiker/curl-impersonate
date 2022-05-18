# curl-impersonate
[![Build and test](https://github.com/lwthiker/curl-impersonate/actions/workflows/build-and-test-make.yml/badge.svg)](https://github.com/lwthiker/curl-impersonate/actions/workflows/build-and-test-make.yml)
[![Docker images](https://github.com/lwthiker/curl-impersonate/actions/workflows/build-and-test-docker.yml/badge.svg)](https://github.com/lwthiker/curl-impersonate/actions/workflows/build-and-test-docker.yml)

A special compilation of [curl](https://github.com/curl/curl) that makes it impersonate real browsers. It can impersonate the four major browsers: Chrome, Edge, Safari & Firefox. This curl binary is able to perform a TLS handshake that is identical to that of a real browser.

## Why?
When you use an HTTP client with a TLS website, it first performs a TLS handshake. The first message of that handshake is called Client Hello. The Client Hello message that curl produces differs drastically from that of a real browser. Compare the following Wireshark capture. Left is a regular curl, right is Firefox.
![curl-ff-before](https://user-images.githubusercontent.com/99899249/154530138-1cba5a23-53d7-4f1a-adc4-7c087e61deb5.png)

Some web services therefore use the TLS handshake to fingerprint which HTTP client is accessing them. Notably, some bot protection platforms use this to identify curl and block it. With the modified curl in this repository, the Client Hello message looks *exactly* like that of a real browser. This tricks TLS fingerprinters to think that it is a real browser that is accessing them.

## How?

The modifications that were needed to make this work:
* Compiling curl with nss, the TLS library that Firefox uses, instead of OpenSSL. For the Chrome version, compiling with BoringSSL.
* Modifying the way curl configures various TLS extensions and SSL options.
* Adding support for new TLS extensions.
* Running curl with some non-default flags, for example `--ciphers`, `--curves` and some `-H` headers.

The resulting curl looks, from a network perspective, identical to a real browser. Compare: (left is `curl-impersonate`, right is Firefox):

![curl-ff-after](https://user-images.githubusercontent.com/99899249/154556768-81bb9dbe-5c3d-4a1c-a0ab-f10a3cd69d9a.png)

Read the full description in the blog post: [part a](https://lwthiker.com/reversing/2022/02/17/curl-impersonate-firefox.html), [part b](https://lwthiker.com/reversing/2022/02/20/impersonating-chrome-too.html).

## Supported browsers
The following browsers can be impersonated.
| Browser | Version | Build | OS | Target name | Wrapper script |
| --- | --- | --- | --- | --- | --- |
| ![Chrome](https://raw.githubusercontent.com/alrra/browser-logos/main/src/chrome/chrome_24x24.png "Chrome") | 99 | 99.0.4844.51 | Windows 10 | `chrome99` | [curl_chrome99](chrome/curl_chrome99) |
| ![Chrome](https://raw.githubusercontent.com/alrra/browser-logos/main/src/chrome/chrome_24x24.png "Chrome") | 100 | 100.0.4896.75 | Windows 10 | `chrome100` | [curl_chrome100](chrome/curl_chrome100) |
| ![Chrome](https://raw.githubusercontent.com/alrra/browser-logos/main/src/chrome/chrome_24x24.png "Chrome") | 101 | 101.0.4951.67 | Windows 10 | `chrome101` | [curl_chrome101](chrome/curl_chrome101) |
| ![Chrome](https://raw.githubusercontent.com/alrra/browser-logos/main/src/chrome/chrome_24x24.png "Chrome") | 99 | 99.0.4844.73 | Android 12 | `chrome99_android` | [curl_chrome99_android](chrome/curl_chrome99_android) |
| ![Edge](https://raw.githubusercontent.com/alrra/browser-logos/main/src/edge/edge_24x24.png "Edge") | 99 | 99.0.1150.30 | Windows 10 | `edge99` | [curl_edge99](chrome/curl_edge99) |
| ![Edge](https://raw.githubusercontent.com/alrra/browser-logos/main/src/edge/edge_24x24.png "Edge") | 101 | 101.0.1210.47 | Windows 10 | `edge101` | [curl_edge101](chrome/curl_edge101) |
| ![Firefox](https://raw.githubusercontent.com/alrra/browser-logos/main/src/firefox/firefox_24x24.png "Firefox") | 91 ESR | 91.6.0esr | Windows 10 | `ff91esr` | [curl_ff91esr](firefox/curl_ff91esr) |
| ![Firefox](https://raw.githubusercontent.com/alrra/browser-logos/main/src/firefox/firefox_24x24.png "Firefox") | 95 | 95.0.2 | Windows 10 | `ff95` | [curl_ff95](firefox/curl_ff95) |
| ![Firefox](https://raw.githubusercontent.com/alrra/browser-logos/main/src/firefox/firefox_24x24.png "Firefox") | 98 | 98.0 | Windows 10 | `ff98` | [curl_ff98](firefox/curl_ff98) |
| ![Firefox](https://raw.githubusercontent.com/alrra/browser-logos/main/src/firefox/firefox_24x24.png "Firefox") | 100 | 100.0 | Windows 10 | `ff100` | [curl_ff100](firefox/curl_ff100) |
| ![Safari](https://github.com/alrra/browser-logos/blob/main/src/safari/safari_24x24.png "Safari") | 15.3 | 16612.4.9.1.8 | MacOS Big Sur | `safari15_3` | [curl_safari15_3](chrome/curl_safari15_3) |

## Basic usage

For each supported browser there is a wrapper script that launches `curl-impersonate` with all the needed headers and flags. For example:
```
curl_chrome99 https://www.wikipedia.org
```
You can add command line flags and they will be passed on to curl. However, some flags change curl's TLS signature which may cause it to be detected.

See [Advanced usage](#Advanced-usage) for more options.

## Installation
There are two versions of `curl-impersonate` for technical reasons. The **chrome** version is used to impersonate Chrome, Edge and Safari. The **firefox** version is used to impersonate Firefox.

### Pre-compiled binaries
Pre-compiled binaries for Linux and macOS (Intel) are available at the [GitHub releases](https://github.com/lwthiker/curl-impersonate/releases) page.

These binaries are statically compiled with libcurl(-impersonate) for ease of use. If you wish to use libcurl-impersonate, please build from source.

### Building from source
See [INSTALL.md](INSTALL.md).

### Docker images
Docker images based on Alpine Linux with `curl-impersonate` compiled and ready to use are available on [Docker Hub](https://hub.docker.com/r/lwthiker/curl-impersonate). The images contain the binary and all the wrapper scripts. Use like the following:
```bash
# Firefox version
docker pull lwthiker/curl-impersonate:0.4-ff
docker run --rm lwthiker/curl-impersonate:0.4-ff curl_ff95 https://www.wikipedia.org

# Chrome version
docker pull lwthiker/curl-impersonate:0.4-chrome
docker run --rm lwthiker/curl-impersonate:0.4-chrome curl_chrome99 https://www.wikipedia.org
```

### Distro packages

AUR packages are available to Arch users: [curl-impersonate-chrome](https://aur.archlinux.org/packages/curl-impersonate-chrome), [curl-impersonate-firefox](https://aur.archlinux.org/packages/curl-impersonate-firefox).

## Advanced usage
### libcurl-impersonate
`libcurl-impersonate.so` is libcurl compiled with the same changes as the command line `curl-impersonate`.
It has an additional API function:
```c
CURLcode curl_easy_impersonate(struct Curl_easy *data, const char *target);
```
You can call it with the target names, e.g. `chrome98`, and it will internally set all the options and headers that are otherwise set by the wrapper scripts. Specifically it sets:
* `CURLOPT_HTTP_VERSION`
* `CURLOPT_SSLVERSION`, `CURLOPT_SSL_CIPHER_LIST`, `CURLOPT_SSL_EC_CURVES`, `CURLOPT_SSL_ENABLE_NPN`, `CURLOPT_SSL_ENABLE_ALPN`
* `CURLOPT_HTTPBASEHEADER`, `CURLOPT_HTTP2_PSEUDO_HEADERS_ORDER` (non-standard HTTP options created for this project).
* `CURLOPT_SSL_ENABLE_ALPS`, `CURLOPT_SSL_SIG_HASH_ALGS`, `CURLOPT_SSL_CERT_COMPRESSION`, `CURLOPT_SSL_ENABLE_TICKET` (non-standard TLS options created for this project).

Note that if you call `curl_easy_setopt()` later with one of the above it will override the options set by `curl_easy_impersonate()`.

### Using CURL_IMPERSONATE env var
*Experimental*: If your application uses `libcurl` already, you can replace the existing library at runtime with `LD_PRELOAD` (Linux only). You can then set the `CURL_IMPERSONATE` env var. For example:
```bash
LD_PRELOAD=/path/to/libcurl-impersonate.so CURL_IMPERSONATE=chrome98 my_app
```
The `CURL_IMPERSONATE` env var has two effects:
* `curl_easy_impersonate()` is called automatically for any new curl handle created by `curl_easy_init()`.
* `curl_easy_impersonate()` is called automatically after any `curl_easy_reset()` call.

This means that all the options needed for impersonation will be automatically set for any curl handle.

Note that the above will NOT WORK for `curl` itself because the curl tool overrides the TLS settings. Use the wrapper scripts instead.

## Contents

This repository contains two main folders:
* [chrome](chrome) - Scripts and patches for building the Chrome version of `curl-impersonate`.
* [firefox](firefox) - Scripts and patches for building the Firefox version of `curl-impersonate`.

The layout is similar for both. For example, the Firefox directory contains:
* [Dockerfile](firefox/Dockerfile) - Used to build `curl-impersonate` with all dependencies.
* [curl_ff91esr](firefox/curl_ff91esr), [curl_ff95](firefox/curl_ff95), [curl_ff98](firefox/curl_ff98) - Wrapper scripts that launch `curl-impersonate` with the correct flags.
* [curl-impersonate.patch](firefox/patches/curl-impersonate.patch) - The main patch that makes curl use the same TLS extensions as Firefox. Also makes curl compile statically with libnghttp2 and libnss.
* [libnghttp2-pc.patch](firefox/patches/libnghttp2-pc.patch) - Patch to make libnghttp2 compile statically.

Other files of interest:
* [tests/signatures.yaml](tests/signatures.yaml) - YAML database of known browser signatures that can be impersonated.

## Contributing
If you'd like to help, please check out the [open issues](https://github.com/lwthiker/curl-impersonate/issues). You can open a pull request with your changes.

This repository contains the build process for `curl-impersonate`. The actual patches to `curl` are maintained in a [separate repository](https://github.com/lwthiker/curl) forked from the upstream curl. The changes are maintained in the [impersonate-firefox](https://github.com/lwthiker/curl/tree/impersonate-firefox)  and [impersonate-chrome](https://github.com/lwthiker/curl/tree/impersonate-chrome) branches.
