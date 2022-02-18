A special compilation of [curl](https://github.com/curl/curl) that makes it impersonate Firefox. This curl binary is able to perform a TLS handshake that is identical to Firefox.

## Why?
When you use an HTTP client with a TLS website, it first performs a TLS handshake. The first message of that handshake is called Client Hello. The Client Hello message that curl produces differs drastically from that of a real browser. Compare the following Wireshark capture. Left is a regular curl, right is Firefox.
![curl-ff-before](https://user-images.githubusercontent.com/99899249/154530138-1cba5a23-53d7-4f1a-adc4-7c087e61deb5.png)

Some web services therefore use the TLS handshake to fingerprint which HTTP client is accessing them. Notably, some bot protection platforms use this to identify curl and block it. With the modified curl in this repository, the Client Hello message looks *exactly* like Firefox's. This tricks TLS fingerprinters to think that it is Firefox that is accessing them, and is able to bypass some well-known bot protections.

## How?

The modifications that were needed to make this work:
* Compiling curl with nss, the TLS library that Firefox uses, instead of OpenSSL.
* Modifying the way curl configures various TLS extensions and SSL options.
* Running curl with some non-default flags, specifically `--http2`, `--ciphers`, and some `-H` headers.

The resulting curl looks, from a network perspective, identical to Firefox (Firefox 95, Windows, non-incognito mode). Compare: (left is `curl-impersonate`, right is Firefox):

![curl-ff-after](https://user-images.githubusercontent.com/99899249/154556768-81bb9dbe-5c3d-4a1c-a0ab-f10a3cd69d9a.png)

Read the full description in the [blog post](https://lwthiker.com/reversing/2022/02/17/curl-impersonate-firefox.html).

## Installation
This repository contains a Dockerfile that will build curl with all the necessary modifications. Build it like any Docker image:
```
docker build -t curl-impersonate .
```

The resulting image contains:
* `/build/out/curl-impersonate` - The curl binary that can impersonate Firefox. It is compiled statically against libcurl, nss, and libnghttp2 so that it won't conflict with any existing libraries on your system. You can use it from the container or copy it out. Tested to work on Ubuntu 20.04.
* `/build/out/curl_ff91esr` - A wrapper script that launches `curl-impersonate` with the needed headers and ciphers to impersonate Firefox 91 ESR (Extended Support Release).
* `/build/out/curl_ff95` - Same but with Firefox 95.

Copy them from the docker image using `docker cp` or use them in a multi-stage docker build.

In addition install libnss3: `sudo apt install libnss3`.  Even though nss is statically compiled into `curl-impersonate`, it is still necessary to install libnss3 because curl dynamically loads `libnssckbi.so`, a file containing Mozilla's list of trusted root certificates. Alternatively, use `curl -k` to disable certificate verification.

## Usage
It is recommended to use the wrapper script `curl_ff91esr` that adds all the correct headers and flags. For example:
```
curl_ff91esr https://www.google.com
```
You can add command line flags and they will be passed on to curl. However, some flags change curl's TLS signature which may cause it to be detected.

## Contents
This repository contains the following files:
* [Dockerfile](Dockerfile) - Used to build `curl-impersonate` with all dependencies.
* [curl_ff91esr](curl_ff91esr), [curl_ff95](curl_ff95) - Wrapper scripts that launch `curl-impersonate` with the correct flags.
* [curl-lib-nss.patch](curl-lib-nss.patch) - The main patch that makes curl use the same TLS extensions as Firefox.
* [libnghttp2-pc.patch](libnghttp2-pc.patch) - Patch to make libnghttp2 compile statically.
* [curl-configure.patch](curl-configure.patch) - Patch to make curl compile with a static libnghttp2.
* [curl-static-libnss.patch](curl-static-libnss.patch) - Patch to make curl compile with a static libnss.

## What's next?
This was done in a very hacky way, but I hope it could be turned into a real project. Imagine that you could run:
```
curl --impersonate ff95
```
and it would behave exactly like Firefox 95. It could then be wrappped with a nice Python library.
