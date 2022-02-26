A special compilation of [curl](https://github.com/curl/curl) that makes it impersonate real browsers. Currently supports Chrome & Firefox. This curl binary is able to perform a TLS handshake that is identical to that of a real browser.

## Why?
When you use an HTTP client with a TLS website, it first performs a TLS handshake. The first message of that handshake is called Client Hello. The Client Hello message that curl produces differs drastically from that of a real browser. Compare the following Wireshark capture. Left is a regular curl, right is Firefox.
![curl-ff-before](https://user-images.githubusercontent.com/99899249/154530138-1cba5a23-53d7-4f1a-adc4-7c087e61deb5.png)

Some web services therefore use the TLS handshake to fingerprint which HTTP client is accessing them. Notably, some bot protection platforms use this to identify curl and block it. With the modified curl in this repository, the Client Hello message looks *exactly* like Chrome's or Firefox's. This tricks TLS fingerprinters to think that it is a real browser that is accessing them.

## How?

The modifications that were needed to make this work:
* Compiling curl with nss, the TLS library that Firefox uses, instead of OpenSSL. For the Chrome version, compiling with BoringSSL.
* Modifying the way curl configures various TLS extensions and SSL options.
* Running curl with some non-default flags, specifically `--http2`, `--ciphers`, and some `-H` headers.

The resulting curl looks, from a network perspective, identical to various browser versions. Compare: (left is `curl-impersonate`, right is Firefox):

![curl-ff-after](https://user-images.githubusercontent.com/99899249/154556768-81bb9dbe-5c3d-4a1c-a0ab-f10a3cd69d9a.png)

Read the full description in the blog post: [part a](https://lwthiker.com/reversing/2022/02/17/curl-impersonate-firefox.html), [part b](https://lwthiker.com/reversing/2022/02/20/impersonating-chrome-too.html).

## Installation
This repository maintains two separate build systems, one for the Chrome version and one for the Firefox version.

### Chrome version
`chrome/Dockerfile` is a Dockerfile that will build curl with all the necessary modifications for impersonating Chrome. Build it like the following:
```
docker build -t curl-impersonate-chrome chrome/
```
The resulting image contains:
* `/build/out/curl-impersonate` - The curl binary that can impersonate Chrome. It is compiled statically against libcurl, BoringSSL, and libnghttp2 so that it won't conflict with any existing libraries on your system. You can use it from the container or copy it out. Tested to work on Ubuntu 20.04.
* `/build/out/curl_chrome98` - A wrapper script that launches `curl-impersonate` with the needed headers and ciphers to impersonate Chrome 98.

You can use them inside the docker, copy them out using `docker cp` or use them in a multi-stage docker build. If you use it outside this container:
* Install dependencies: `sudo apt install libbrotli1`


### Firefox version
Build with:
```
docker build -t curl-impersonate-ff firefox/
```
The resulting image contains:
* `/build/out/curl-impersonate` - The curl binary that can impersonate Firefox. It is compiled statically against libcurl, nss, and libnghttp2 so that it won't conflict with any existing libraries on your system. You can use it from the container or copy it out. Tested to work on Ubuntu 20.04.
* `/build/out/curl_ff91esr` - A wrapper script that launches `curl-impersonate` with the needed headers and ciphers to impersonate Firefox 91 ESR (Extended Support Release).
* `/build/out/curl_ff95` - Same but with Firefox 95.

If you use it outside this container:
* Install dependencies: `sudo apt install libbrotli1`
* Install libnss3: `sudo apt install libnss3`.  Even though nss is statically compiled into `curl-impersonate`, it is still necessary to install libnss3 because curl dynamically loads `libnssckbi.so`, a file containing Mozilla's list of trusted root certificates. Alternatively, use `curl -k` to disable certificate verification.

### Distro packages

AUR packages are available to Arch users: [curl-impersonate-chrome](https://aur.archlinux.org/packages/curl-impersonate-chrome), [curl-impersonate-firefox](https://aur.archlinux.org/packages/curl-impersonate-firefox).

## Usage
It is recommended to use the wrapper scripts `curl_chrome98` or `curl_ff91esr`, as they add all the correct headers and flags. For example:
```
curl_chrome98 https://www.google.com
```
You can add command line flags and they will be passed on to curl. However, some flags change curl's TLS signature which may cause it to be detected.

## Contents

This repository contains two main folders:
* [chrome](chrome) - Scripts and patches for building the Chrome version of `curl-impersonate`.
* [firefox](firefox) - Scripts and patches for building the Firefox version of `curl-impersonate`.

The layout is similar for both. For example, the Firefox directory contains:
* [Dockerfile](firefox/Dockerfile) - Used to build `curl-impersonate` with all dependencies.
* [curl_ff91esr](firefox/curl_ff91esr), [curl_ff95](curl_ff95) - Wrapper scripts that launch `curl-impersonate` with the correct flags.
* [curl-impersonate.patch](firefox/patches/curl-impersonate.patch) - The main patch that makes curl use the same TLS extensions as Firefox. Also makes curl compile statically with libnghttp2 and libnss.
* [libnghttp2-pc.patch](firefox/patches/libnghttp2-pc.patch) - Patch to make libnghttp2 compile statically.

Other files of interest:
* [tests/signatures.yaml](tests/signatures.yaml) - YAML database of known browser signatures that can be impersonated.

## Contributing
If you'd like to help, please check out the [open issues](https://github.com/lwthiker/curl-impersonate/issues). You can open a pull request with your changes.

This repository contains the build process for `curl-impersonate`. The actual patches to `curl` are maintained in a [separate repository](https://github.com/lwthiker/curl) forked from the upstream curl. The changes are maintained in the [impersonate-firefox](https://github.com/lwthiker/curl/tree/impersonate-firefox)  and [impersonate-chrome](https://github.com/lwthiker/curl/tree/impersonate-chrome) branches.
