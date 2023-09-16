# Running curl-impersonate from the command line

curl-impersonate can be run from the command line just like the regular curl tool.
Since it is just a modified curl build, all the original flags and command line options are supported.

For example, the Firefox version can be run as follows:
```bash
curl-impersonate-ff -v -L https://wikipedia.org
```

and the Chrome version:
```bash
curl-impersonate-chrome -v -L https://wikipedia.org
```

However, by default, running the binaries as above will not prdouce the same TLS and HTTP/2 signatures as the impersonated browsers. Rather, this project provides additional *wrapper scripts* that launch these binaries with the correct set of command line flags to produce the desired signatures. For example:
```bash
curl_chrome104 -v -L https://wikipedia.org
```

will produce a signature identical to Chrome version 104. You can add command line flags and they will be passed on to curl. However, some flags change curl's TLS signature. See below for more details.

The full list of wrapper scripts is available on the [main page](https://github.com/lwthiker/curl-impersonate#supported-browsers).

## Changing the HTTP headers
The wrapper scripts use a certain set of HTTP headers such as `User-Agent`, `Accept-Encoding` and a few more.
These headers were chosen to be identical to the default set of headers used by the browser upon requesting an unvisited website. The order of the headers was chosen to match as well.

In many different scenarios you may wish to change the headers, their order, or to add new ones.
To do so correctly, currently the best option is to modify the scripts.
Otherwise you may get duplicate headers or a wrong order of headers.

## How the wrapper scripts work
Let's analyze the contents of the `curl_chrome104` wrapper script.
Understanding this can help in some scenarios where better control of the signature is needed.

The important part of the script is:
```bash
"$dir/curl-impersonate-chrome" \
    --ciphers TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256,ECDHE-ECDSA-AES128-GCM-SHA256,ECDHE-RSA-AES128-GCM-SHA256,ECDHE-ECDSA-AES256-GCM-SHA384,ECDHE-RSA-AES256-GCM-SHA384,ECDHE-ECDSA-CHACHA20-POLY1305,ECDHE-RSA-CHACHA20-POLY1305,ECDHE-RSA-AES128-SHA,ECDHE-RSA-AES256-SHA,AES128-GCM-SHA256,AES256-GCM-SHA384,AES128-SHA,AES256-SHA \
    -H 'sec-ch-ua: "Chromium";v="104", " Not A;Brand";v="99", "Google Chrome";v="104"' \
    -H 'sec-ch-ua-mobile: ?0' \
    -H 'sec-ch-ua-platform: "Windows"' \
    -H 'Upgrade-Insecure-Requests: 1' \
    -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36' \
    -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9' \
    -H 'Sec-Fetch-Site: none' \
    -H 'Sec-Fetch-Mode: navigate' \
    -H 'Sec-Fetch-User: ?1' \
    -H 'Sec-Fetch-Dest: document' \
    -H 'Accept-Encoding: gzip, deflate, br' \
    -H 'Accept-Language: en-US,en;q=0.9' \
    --http2 --compressed \
    --tlsv1.2 --no-npn --alps \
    --cert-compression brotli \
    "$@"
```

The important flags are as follows:
* `--ciphers` controls the cipher list, an important part of the TLS client hello message. The ciphers were chosen to match Chrome's.
* The multiple `-H` flags set the HTTP headers. You may want to modify these in many scenarios where other HTTP headers are required.
* `--tlsv1.2` sets the minimal TLS version, which is part of the TLS client hello message, to TLS1.2.
* `--no-npn` disables to NPN TLS extension.
* `--alps` enables the ALPS TLS extension. This flag was added for this project.
* `--cert-compression` enables TLS certificate compression used by Chrome. This flag was added for this project.

## Flags that modify the TLS signature

The following flags are known to affect the TLS signature of curl.
Using them in addition to the flags in the wrapper scripts may produce a signature that does not match the browser.

`--ciphers`, `--curves`, `--no-npn`, `--no-alpn`, `--tls-max`, `--tls13-ciphers`, `--tlsv1.0`, `--tlsv1.1`, `--tlsv1.2`, `--tlsv1.3`, `--tlsv1`
