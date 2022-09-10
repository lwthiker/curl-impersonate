# Using libcurl-impersonate in PHP scripts

It is possible to use libcurl-impersonate in PHP scripts instead of the original libcurl. PHP loads libcurl dynamically during runtime, which means that a different set of steps needs to be taken.

## On Linux

First, patch libcurl-impersonate and change its SONAME:
```bash
patchelf --set-soname libcurl.so.4 /path/to/libcurl-impersonate-chrome.so
```

Then replace at runtime with:
```bash
LD_PRELOAD=/path/to/libcurl-impersonate-chrome.so CURL_IMPERSONATE=chrome101 php -r 'print_r(curl_version());'
```

If successful you should see:
```
[ssl_version] => BoringSSL
```
(or NSS if the Firefox version is used)

## On macOS

On Mac, first rename `libcurl-impersonate-chrome.dylib` to `libcurl.4.dylib` and place in some directory, say `/usr/local/lib`. Then run php with the `DYLD_LIBRARY_PATH` env var pointing to that directory, for example:
```
DYLD_LIBRARY_PATH=/usr/local/lib php -r 'print_r(curl_version());'
```

If successful you should see:
```
[ssl_version] => BoringSSL
```
