# curl-impersonate ![Chrome](https://raw.githubusercontent.com/alrra/browser-logos/main/src/chrome/chrome_24x24.png "Chrome") ![Edge](https://raw.githubusercontent.com/alrra/browser-logos/main/src/edge/edge_24x24.png "Edge") ![Firefox](https://raw.githubusercontent.com/alrra/browser-logos/main/src/firefox/firefox_24x24.png "Firefox") ![Safari](https://github.com/alrra/browser-logos/blob/main/src/safari/safari_24x24.png "Safari")
[![Build and test](https://github.com/lwthiker/curl-impersonate/actions/workflows/build-and-test-make.yml/badge.svg)](https://github.com/lwthiker/curl-impersonate/actions/workflows/build-and-test-make.yml)
[![Docker images](https://github.com/lwthiker/curl-impersonate/actions/workflows/build-and-test-docker.yml/badge.svg)](https://github.com/lwthiker/curl-impersonate/actions/workflows/build-and-test-docker.yml)

A special build of [curl](https://github.com/curl/curl) that can impersonate the four major browsers: Chrome, Edge, Safari & Firefox. curl-impersonate is able to perform TLS and HTTP handshakes that are identical to that of a real browser.

curl-impersonate can be used either as a command line tool, similar to the regular curl, or as a library that can be integrated instead of the regular libcurl. See [Usage](#Basic-usage) below.

## Why?
When you use an HTTP client with a TLS website, it first performs a TLS handshake. The first message of that handshake is called Client Hello. The Client Hello message that most HTTP clients and libraries produce differs drastically from that of a real browser.

If the server uses HTTP/2, then in addition to the TLS handshake there is also an HTTP/2 handshake where various settings are exchanged. The settings that most HTTP clients and libraries use differ as well from those of any real browsers.

For these reasons, some web services use the TLS and HTTP handshakes to fingerprint which client is accessing them, and then present different content for different clients. These methods are known as [TLS fingerprinting](https://lwthiker.com/networks/2022/06/17/tls-fingerprinting.html) and [HTTP/2 fingerprinting](https://lwthiker.com/networks/2022/06/17/http2-fingerprinting.html) respectively. Their widespread use has led to the web becoming less open, less private and much more restrictive towards specific web clients

With the modified curl in this repository, the TLS and HTTP handshakes look *exactly* like those of a real browser.

## How?

To make this work, `curl` was patched significantly to resemble a browser. Specifically, The modifications that were needed to make this work:
* Compiling curl with nss, the TLS library that Firefox uses, instead of OpenSSL. For the Chrome version, compiling with BoringSSL, Google's TLS library.
* Modifying the way curl configures various TLS extensions and SSL options.
* Adding support for new TLS extensions.
* Changing the settings that curl uses for its HTTP/2 connections.
* Running curl with some non-default flags, for example `--ciphers`, `--curves` and some `-H` headers.

The resulting curl looks, from a network perspective, identical to a real browser.

Read the full technical description in the blog posts: [part a](https://lwthiker.com/reversing/2022/02/17/curl-impersonate-firefox.html), [part b](https://lwthiker.com/reversing/2022/02/20/impersonating-chrome-too.html).

## Supported browsers
The following browsers can be impersonated.
| Browser | Version | Build | OS | Target name | Wrapper script |
| --- | --- | --- | --- | --- | --- |
| ![Chrome](https://raw.githubusercontent.com/alrra/browser-logos/main/src/chrome/chrome_24x24.png "Chrome") | 99 | 99.0.4844.51 | Windows 10 | `chrome99` | [curl_chrome99](chrome/curl_chrome99) |
| ![Chrome](https://raw.githubusercontent.com/alrra/browser-logos/main/src/chrome/chrome_24x24.png "Chrome") | 100 | 100.0.4896.75 | Windows 10 | `chrome100` | [curl_chrome100](chrome/curl_chrome100) |
| ![Chrome](https://raw.githubusercontent.com/alrra/browser-logos/main/src/chrome/chrome_24x24.png "Chrome") | 101 | 101.0.4951.67 | Windows 10 | `chrome101` | [curl_chrome101](chrome/curl_chrome101) |
| ![Chrome](https://raw.githubusercontent.com/alrra/browser-logos/main/src/chrome/chrome_24x24.png "Chrome") | 104 | 104.0.5112.81 | Windows 10 | `chrome104` | [curl_chrome104](chrome/curl_chrome104) |
| ![Chrome](https://raw.githubusercontent.com/alrra/browser-logos/main/src/chrome/chrome_24x24.png "Chrome") | 107 | 107.0.5304.107 | Windows 10 | `chrome107` | [curl_chrome107](chrome/curl_chrome107) |
| ![Chrome](https://raw.githubusercontent.com/alrra/browser-logos/main/src/chrome/chrome_24x24.png "Chrome") | 110 | 110.0.5481.177 | Windows 10 | `chrome110` | [curl_chrome110](chrome/curl_chrome110) |
| ![Chrome](https://raw.githubusercontent.com/alrra/browser-logos/main/src/chrome/chrome_24x24.png "Chrome") | 116 | 116.0.5845.180 | Windows 10 | `chrome116` | [curl_chrome116](chrome/curl_chrome116) |
| ![Chrome](https://raw.githubusercontent.com/alrra/browser-logos/main/src/chrome/chrome_24x24.png "Chrome") | 99 | 99.0.4844.73 | Android 12 | `chrome99_android` | [curl_chrome99_android](chrome/curl_chrome99_android) |
| ![Edge](https://raw.githubusercontent.com/alrra/browser-logos/main/src/edge/edge_24x24.png "Edge") | 99 | 99.0.1150.30 | Windows 10 | `edge99` | [curl_edge99](chrome/curl_edge99) |
| ![Edge](https://raw.githubusercontent.com/alrra/browser-logos/main/src/edge/edge_24x24.png "Edge") | 101 | 101.0.1210.47 | Windows 10 | `edge101` | [curl_edge101](chrome/curl_edge101) |
| ![Firefox](https://raw.githubusercontent.com/alrra/browser-logos/main/src/firefox/firefox_24x24.png "Firefox") | 91 ESR | 91.6.0esr | Windows 10 | `ff91esr` | [curl_ff91esr](firefox/curl_ff91esr) |
| ![Firefox](https://raw.githubusercontent.com/alrra/browser-logos/main/src/firefox/firefox_24x24.png "Firefox") | 95 | 95.0.2 | Windows 10 | `ff95` | [curl_ff95](firefox/curl_ff95) |
| ![Firefox](https://raw.githubusercontent.com/alrra/browser-logos/main/src/firefox/firefox_24x24.png "Firefox") | 98 | 98.0 | Windows 10 | `ff98` | [curl_ff98](firefox/curl_ff98) |
| ![Firefox](https://raw.githubusercontent.com/alrra/browser-logos/main/src/firefox/firefox_24x24.png "Firefox") | 100 | 100.0 | Windows 10 | `ff100` | [curl_ff100](firefox/curl_ff100) |
| ![Firefox](https://raw.githubusercontent.com/alrra/browser-logos/main/src/firefox/firefox_24x24.png "Firefox") | 102 | 102.0 | Windows 10 | `ff102` | [curl_ff102](firefox/curl_ff102) |
| ![Firefox](https://raw.githubusercontent.com/alrra/browser-logos/main/src/firefox/firefox_24x24.png "Firefox") | 109 | 109.0 | Windows 10 | `ff109` | [curl_ff109](firefox/curl_ff109) |
| ![Firefox](https://raw.githubusercontent.com/alrra/browser-logos/main/src/firefox/firefox_24x24.png "Firefox") | 117 | 117.0.1 | Windows 10 | `ff117` | [curl_ff117](firefox/curl_ff117) |
| ![Safari](https://github.com/alrra/browser-logos/blob/main/src/safari/safari_24x24.png "Safari") | 15.3 | 16612.4.9.1.8 | MacOS Big Sur | `safari15_3` | [curl_safari15_3](chrome/curl_safari15_3) |
| ![Safari](https://github.com/alrra/browser-logos/blob/main/src/safari/safari_24x24.png "Safari") | 15.5 | 17613.2.7.1.8 | MacOS Monterey | `safari15_5` | [curl_safari15_5](chrome/curl_safari15_5) |

This list is also available in the [browsers.json](browsers.json) file.

## Basic usage

For each supported browser there is a wrapper script that launches `curl-impersonate` with all the needed headers and flags. For example:
```
curl_chrome116 https://www.wikipedia.org
```
You can add command line flags and they will be passed on to curl. However, some flags change curl's TLS signature which may cause it to be detected.

Please note that the wrapper scripts use a default set of HTTP headers. If you want to change these headers, you may want to modify the wrapper scripts to fit your own purpose.

See [Advanced usage](#Advanced-usage) for more options, including using `libcurl-impersonate` as a library.

## Documentation

More documentation is available in the [docs/](docs/README.md) directory.

## Installation
There are two versions of `curl-impersonate` for technical reasons. The **chrome** version is used to impersonate Chrome, Edge and Safari. The **firefox** version is used to impersonate Firefox.

### Pre-compiled binaries
Pre-compiled binaries for Linux and macOS (Intel) are available at the [GitHub releases](https://github.com/lwthiker/curl-impersonate/releases) page. Before you use them you need to install nss (Firefox's TLS library) and CA certificates:
* Ubuntu - `sudo apt install libnss3 nss-plugin-pem ca-certificates`
* Red Hat/Fedora/CentOS - `yum install nss nss-pem ca-certificates`
* Archlinux - `pacman -S nss ca-certificates`
* macOS - `brew install nss ca-certificates`

The pre-compiled binaries contain libcurl-impersonate and a statically compiled curl-impersonate for ease of use.

The pre-compiled Linux binaries are built for Ubuntu systems. On other distributions if you have errors with certificate verification you may have to tell curl where to find the CA certificates. For example:
```
curl_chrome116 https://www.wikipedia.org --cacert /etc/ssl/certs/ca-bundle.crt
```

Also make sure to read [Notes on Dependencies](#notes-on-dependencies).

### Building from source
See [INSTALL.md](INSTALL.md).

### Docker images
Docker images based on Alpine Linux and Debian with `curl-impersonate` compiled and ready to use are available on [Docker Hub](https://hub.docker.com/r/lwthiker/curl-impersonate). The images contain the binary and all the wrapper scripts. Use like the following:
```bash
# Firefox version, Alpine Linux
docker pull lwthiker/curl-impersonate:0.5-ff
docker run --rm lwthiker/curl-impersonate:0.5-ff curl_ff109 https://www.wikipedia.org

# Chrome version, Alpine Linux
docker pull lwthiker/curl-impersonate:0.5-chrome
docker run --rm lwthiker/curl-impersonate:0.5-chrome curl_chrome110 https://www.wikipedia.org
```

### Distro packages
AUR packages are available to Archlinux users:
* Pre-compiled package: [curl-impersonate-bin](https://aur.archlinux.org/packages/curl-impersonate-bin), [libcurl-impersonate-bin](https://aur.archlinux.org/packages/libcurl-impersonate-bin).
* Build from source code: [curl-impersonate-chrome](https://aur.archlinux.org/packages/curl-impersonate-chrome), [curl-impersonate-firefox](https://aur.archlinux.org/packages/curl-impersonate-firefox).

## Advanced usage
### libcurl-impersonate
`libcurl-impersonate.so` is libcurl compiled with the same changes as the command line `curl-impersonate`.
It has an additional API function:
```c
CURLcode curl_easy_impersonate(struct Curl_easy *data, const char *target,
                               int default_headers);
```
You can call it with the target names, e.g. `chrome116`, and it will internally set all the options and headers that are otherwise set by the wrapper scripts.
If `default_headers` is set to 0, the built-in list of  HTTP headers will not be set, and the user is expected to provide them instead using the regular [`CURLOPT_HTTPHEADER`](https://curl.se/libcurl/c/CURLOPT_HTTPHEADER.html) libcurl option.

Calling the above function sets the following libcurl options:
* `CURLOPT_HTTP_VERSION`
* `CURLOPT_SSLVERSION`, `CURLOPT_SSL_CIPHER_LIST`, `CURLOPT_SSL_EC_CURVES`, `CURLOPT_SSL_ENABLE_NPN`, `CURLOPT_SSL_ENABLE_ALPN`
* `CURLOPT_HTTPBASEHEADER`, if `default_headers` is non-zero (this is a non-standard HTTP option created for this project).
* `CURLOPT_HTTP2_PSEUDO_HEADERS_ORDER`, `CURLOPT_HTTP2_NO_SERVER_PUSH` (non-standard HTTP/2 options created for this project).
* `CURLOPT_SSL_ENABLE_ALPS`, `CURLOPT_SSL_SIG_HASH_ALGS`, `CURLOPT_SSL_CERT_COMPRESSION`, `CURLOPT_SSL_ENABLE_TICKET` (non-standard TLS options created for this project).
* `CURLOPT_SSL_PERMUTE_EXTENSIONS` (non-standard TLS options created for this project).
Note that if you call `curl_easy_setopt()` later with one of the above it will override the options set by `curl_easy_impersonate()`.

### Using CURL_IMPERSONATE env var
If your application uses `libcurl` already, you can replace the existing library at runtime with `LD_PRELOAD` (Linux only). You can then set the `CURL_IMPERSONATE` env var. For example:
```bash
LD_PRELOAD=/path/to/libcurl-impersonate.so CURL_IMPERSONATE=chrome116 my_app
```
The `CURL_IMPERSONATE` env var has two effects:
* `curl_easy_impersonate()` is called automatically for any new curl handle created by `curl_easy_init()`.
* `curl_easy_impersonate()` is called automatically after any `curl_easy_reset()` call.

This means that all the options needed for impersonation will be automatically set for any curl handle.

If you need precise control over the HTTP headers, set `CURL_IMPERSONATE_HEADERS=no` to disable the built-in list of HTTP headers, then set them yourself with `curl_easy_setopt()`. For example:
```bash
LD_PRELOAD=/path/to/libcurl-impersonate.so CURL_IMPERSONATE=chrome116 CURL_IMPERSONATE_HEADERS=no my_app
```

Note that the `LD_PRELOAD` method will NOT WORK for `curl` itself because the curl tool overrides the TLS settings. Use the wrapper scripts instead.

### Notes on dependencies 

If you intend to copy the self-compiled artifacts to another system, or use the [Pre-compiled binaries](#pre-compiled-binaries) provided by the project, make sure that all the additional dependencies are met on the target system as well. 
In particular, see the [note about the Firefox version](INSTALL.md#a-note-about-the-firefox-version).

## Contents

This repository contains two main folders:
* [chrome](chrome) - Scripts and patches for building the Chrome version of `curl-impersonate`.
* [firefox](firefox) - Scripts and patches for building the Firefox version of `curl-impersonate`.

The layout is similar for both. For example, the Firefox directory contains:
* [Dockerfile](firefox/Dockerfile) - Used to build `curl-impersonate` with all dependencies.
* [curl_ff91esr](firefox/curl_ff91esr), [curl_ff95](firefox/curl_ff95), [curl_ff98](firefox/curl_ff98) - Wrapper scripts that launch `curl-impersonate` with the correct flags.
* [curl-impersonate.patch](firefox/patches/curl-impersonate.patch) - The main patch that makes curl use the same TLS extensions as Firefox. Also makes curl compile statically with libnghttp2 and libnss.

Other files of interest:
* [tests/signatures](tests/signatures) - YAML database of known browser signatures that can be impersonated.

## Contributing
If you'd like to help, please check out the [open issues](https://github.com/lwthiker/curl-impersonate/issues). You can open a pull request with your changes.

This repository contains the build process for `curl-impersonate`. The actual patches to `curl` are maintained in a [separate repository](https://github.com/lwthiker/curl) forked from the upstream curl. The changes are maintained in the [impersonate-firefox](https://github.com/lwthiker/curl/tree/impersonate-firefox)  and [impersonate-chrome](https://github.com/lwthiker/curl/tree/impersonate-chrome) branches.

## Sponsors
Sponsors help keep this project open and maintained. If you wish to become a sponsor, please contact me directly at: lwt at lwthiker dot com.

<a href="https://serpapi.com/">
  <img src="https://i.imgur.com/CBOSxrm.png" alt="Logo"  width="165px" height="65px">
</a>
