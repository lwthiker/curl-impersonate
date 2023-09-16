# Building and installing curl-impersonate

This guide shows how to compile and install curl-impersonate and libcurl-impersonate from source.
The build process takes care of downloading dependencies, patching them, compiling them and finally compiling curl itself with the needed patches.
There are currently three build options depending on your use case:

* [Native build](#native-build) using an autotools-based Makefile
* [Cross compiling](#cross-compiling) using an autotools-based Makefile
* [Docker container build](#docker-build)

There are two versions of `curl-impersonate` for technical reasons. The **chrome** version is used to impersonate Chrome, Edge and Safari. The **firefox** version is used to impersonate Firefox.

## Native build

### Ubuntu

Install dependencies for building all the components:

```sh
sudo apt install build-essential pkg-config cmake ninja-build curl autoconf automake libtool
# For the Firefox version only
sudo apt install python3-pip libnss3
pip install gyp-next
export PATH="$PATH:~/.local/bin" # Add gyp to PATH
# For the Chrome version only
sudo apt install golang-go unzip
```

Clone this repository:

```sh
git clone https://github.com/lwthiker/curl-impersonate.git
cd curl-impersonate
```

Configure and compile:

```sh
mkdir build && cd build
../configure
# Build and install the Firefox version
make firefox-build
sudo make firefox-install
# Build and install the Chrome version
make chrome-build
sudo make chrome-install
# You may need to update the linker's cache to find libcurl-impersonate
sudo ldconfig
# Optionally remove all the build files
cd ../ && rm -Rf build
```

This will install curl-impersonate, libcurl-impersonate and the wrapper scripts to `/usr/local`. To change the installation path, pass `--prefix=/path/to/install/` to the `configure` script.

After installation you can run the wrapper scripts, e.g.:

```sh
curl_ff98 https://www.wikipedia.org
curl_chrome99 https://www.wikipedia.org
```

or run directly with you own flags:

```sh
curl-impersonate-ff https://www.wikipedia.org
curl-impersonate-chrome https://www.wikipedia.org
```

### Red Hat based (CentOS/Fedora/Amazon Linux)

Install dependencies:

```sh
yum groupinstall "Development Tools"
yum groupinstall "C Development Tools and Libraries" # Fedora only
yum install cmake3 python3 python3-pip
# Install Ninja. This may depend on your system.
yum install ninja-build
# OR
pip3 install ninja
```

For the Firefox version, install NSS and gyp:

```sh
yum install nss nss-pem
pip3 install gyp-next
```

For the Chrome version, install Go.
You may need to follow the [Go installation instructions](https://go.dev/doc/install) if it's not packaged for your system:

```sh
yum install golang
```

Then follow the 'Ubuntu' instructions for the actual build.

### macOS

Install dependencies for building all the components:

```sh
brew install pkg-config make cmake ninja autoconf automake libtool
# For the Firefox version only
brew install sqlite nss
pip3 install gyp-next
# For the Chrome version only
brew install go
```

Clone this repository:
```
git clone https://github.com/lwthiker/curl-impersonate.git
cd curl-impersonate
```

Configure and compile:

```sh
mkdir build && cd build
../configure
# Build and install the Firefox version
gmake firefox-build
sudo gmake firefox-install
# Build and install the Chrome version
gmake chrome-build
sudo gmake chrome-install
# Optionally remove all the build files
cd ../ && rm -Rf build
```

### Static compilation

To compile curl-impersonate statically with libcurl-impersonate, pass `--enable-static` to the `configure` script.

### A note about the Firefox version

The Firefox version compiles a static version of nss, Firefox's TLS library.
For NSS to have a list of root certificates, curl attempts to load at runtime `libnssckbi`, one of the NSS libraries.
If you get the error:

```sh
curl: (60) Peer's Certificate issuer is not recognized
```

or

```sh
curl: (77) Problem with the SSL CA cert (path? access rights?)
```

, make sure that NSS is installed (see above).
If the issue persists it might be that NSS is installed in a non-standard location on your system.
Please open an issue in that case.

## Cross compiling

There is some basic support for cross compiling curl-impersonate.
It is currently being used to build curl-impersonate for ARM64 (aarch64) systems from x86-64 systems.
Cross compiling is similar to the usual build but a bit trickier:

* You'd have to build zlib for the target architecture so that curl can link with it.
* Some paths have to be specified manually since curl's own build system can't determine their location.

An example build for aarch64 on Ubuntu x86_64:

```sh
sudo apt-get install gcc-aarch64-linux-gnu g++-aarch64-linux-gnu

./configure --host=aarch64-linux-gnu \
            --with-zlib=/path/to/compiled/zlib \
            --with-ca-path=/etc/ssl/certs \
            --with-ca-bundle=/etc/ssl/certs/ca-certificates.crt \
            --with-libnssckbi=/usr/lib/aarch64-linux-gnu/nss

make chrome-build
make firefox-build
```

The flags mean as follows:
`--with-zlib` is the location of a compiled zlib library for the target architecture.
`--with-ca-path` and `--with-ca-bundle` will be passed to curl's configure script as is.
`--with-libnssckbi` indicates the location of libnssckbi.so on the target system. This file contains the certificates needed by curl. This must be supplied if NSS is not installed in a standard location (i.e. not in `/usr/lib`).

## Docker build

The Docker build is a bit more reproducible and serves as the reference implementation. It creates a Debian-based Docker image with the binaries.

### Chrome version

[`chrome/Dockerfile`](chrome/Dockerfile) is a debian-based Dockerfile that will build curl with all the necessary modifications and patches. Build it like the following:

```sh
docker build -t curl-impersonate-chrome chrome/
```

The resulting binaries and libraries are in the `/usr/local` directory, which contains:

* `curl-impersonate-chrome`, `curl-impersonate` - The curl binary that can impersonate Chrome/Edge/Safari. It is compiled statically against libcurl, BoringSSL, and libnghttp2 so that it won't conflict with any existing libraries on your system. You can use it from the container or copy it out. Tested to work on Ubuntu 20.04.
* `curl_chrome99`, `curl_chrome100`, `...` - Wrapper scripts that launch `curl-impersonate` with all the needed flags.
* `libcurl-impersonate-chrome.so`, `libcurl-impersonate.so` - libcurl compiled with impersonation support. See [libcurl-impersonate](README.md#libcurl-impersonate) for more details.

You can use them inside the docker, copy them out using `docker cp` or use them in a multi-stage docker build.

### Firefox version

Build with:

```sh
docker build -t curl-impersonate-ff firefox/
```

The resulting binaries and libraries are in the `/usr/local` directory, which contains:

* `curl-impersonate-ff`, `curl-impersonate` - The curl binary that can impersonate Firefox. It is compiled statically against libcurl, nss, and libnghttp2 so that it won't conflict with any existing libraries on your system. You can use it from the container or copy it out. Tested to work on Ubuntu 20.04.
* `curl_ff91esr`, `curl_ff95`, `...` - Wrapper scripts that launch `curl-impersonate` with all the needed flags.
* `libcurl-impersonate-ff.so`, `libcurl-impersonate.so` - libcurl compiled with impersonation support. See [libcurl-impersonate](README.md#libcurl-impersonate) for more details.

If you use it outside the container, install the following dependency:

* `sudo apt install libnss3`.  Even though nss is statically compiled into `curl-impersonate`, it is still necessary to install libnss3 because curl dynamically loads `libnssckbi.so`, a file containing Mozilla's list of trusted root certificates. Alternatively, use `curl -k` to disable certificate verification.
