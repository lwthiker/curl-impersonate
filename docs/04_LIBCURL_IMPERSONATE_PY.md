# Using curl-impersonate with [PyCurl](http://pycurl.io/)

It is possible to use curl-impersonate in python scripts with the help of pycurl. 
Pass the curl-impersonate config with the ‘–curl-config’ command line option to specify the file location.

## Docker
```dockerfile
# Replaced line 140 on the original chrome/Dockerfile
FROM python:3.10-buster
RUN apt-get update && apt-get install -y ca-certificates
# Copy curl-impersonate from the builder image
COPY --from=builder /build/install /usr/local
# Update the loader's cache
RUN ldconfig
# Copy to /build/out as well for backward compatibility with previous versions.
COPY --from=builder /build/out /build/out
# Wrapper scripts
COPY --from=builder /build/out/curl_* /usr/local/bin/

RUN git clone https://github.com/pycurl/pycurl.git
RUN cd pycurl && python3 setup.py install --curl-config=/usr/local/bin/curl-impersonate-chrome-config
```

## Linux
```bash
git clone https://github.com/pycurl/pycurl.git
cd pycurl && python3 setup.py install --curl-config=/path/to/curl-chrome/curl-impersonate-chrome-config
```

## Output
```python
import pycurl
pycurl.version_info() 
# (9, '7.84.0', 480256, 'x86_64-pc-linux-gnu', 1370063517, 'BoringSSL', 0, '1.2.11', ('dict', 'file', 'ftp', 'ftps', 'gopher', 'gophers', 'http', 'https', 'imap', 'imaps', 'mqtt', 'pop3', 'pop3s', 'rtsp', 'smb', 'smbs', 'smtp', 'smtps', 'telnet', 'tftp'), None, 0, None)
```
