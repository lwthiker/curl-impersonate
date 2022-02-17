A special compilation of curl that makes it impersonate Firefox. This curl binary is able to send the EXACT same TLS handshake as Firefox.

## Why?

[ PLACEHOLDER ]

Read the full description in the blog post.

## How?

The modifications that were needed to make this work:
* Compiling curl with nss, the TLS library that Firefox uses, instead of OpenSSL.
* Modifying the way curl configures various TLS extensions and SSL options.
* Running curl with some non-default flags, specifically `--http2`, `--ciphers`, and specific `-H` headers.

The resulting curl looks, from a network perspective, identical to Firefox (Firefox 95, Windows, non-incognito mode).

## Installation
This repository contains a Dockerfile that will build curl with all the necessary modifications. Build it like any Docker image:
```
docker build -t curl-impersonate .
```

The resulting image contains:
* `/build/out/curl-nss` - The curl binary that can impersonate Firefox. It is compiled statically against libcurl, nss, and libnghttp2 so that it won't conflict with any existing libraries on your system. You can use it from the container or copy it out. Tested to work on Ubuntu 20.04.
* `/build/out/curl_ff95` - A wrapper script that launches `curl-nss` with the needed headers and ciphers to impersonate Firefox 95.

Copy them from the docker image using `docker cp` or use them in a multi-stage docker build.

In addition install libnss3: `sudo apt install libnss3`.  Even though nss is statically compiled into curlnss, it is still necessary to install libnss3 because curl searches for `libnssckbi.so`, a file containing Mozilla's list of trusted root certificates. Alternatively, use `curl -k` to disable certificate verification.

## Usage
It is recommended to use the wrapper script `curl_ff95` that adds all the correct headers and flags. Any flag that you add will be given to the real curl. For example:
```
curl_ff95 -sL https://www.google.com
```

## Details
This repository contains the following files:
* Dockerfile - Used to build `curl-nss` with all dependencies.
* curl_ff95 - Wrapper script that launches `curl-nss` with the correct flags.
* curl-lib-nss.patch - The main patch that makes curl use the same TLS extensions as Firefox.
* libnghttp2-pc.patch - Patch to make libnghttp2 compile statically.
* curl-configure.patch - Patch to make curl compile with a static libnghttp2.
* curl-static-libnss.patch - Patch to make curl compile with a static libnss.

## What's next?
This was done in a very hacky way, but I hope the findings below could be turned into real project. Imagine that you could run:
```
curl --impersonate ff95
```
and it would behave exactly like Firefox 95. It can then be wrappped with a nice Python library.
