# Building and installing curl-impersonate

This guide shows how to compile and install curl-impersonate and libcurl-impersonate from source.
The build process takes care of downloading dependencies, patching them, compiling them and finally compiling curl itself with the needed patches.
There are currently two build options depending on your use case:
* Native build using Makefile
* Docker container build

There are two versions of `curl-impersonate` for technical reasons. The **chrome** version is used to impersonate Chrome, Edge and Safari. The **firefox** version is used to impersonate Firefox.

## Native build

### Linux (Ubuntu)

Install dependencies for building all the components:
```
sudo apt install build-essential pkg-config cmake ninja-build curl autoconf automake libtool
# For the Firefox version only
sudo apt install python3-pip
pip install gyp-next
export PATH="$PATH:~/.local/bin" # Add gyp to PATH
# For the Chrome version only
sudo apt install golang-go
```

Clone this repository:
```
git clone https://github.com/lwthiker/curl-impersonate.git
cd curl-impersonate
```

Generate the configure script:
```
autoconf
```

Configure and compile:
```
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
```
curl_ff98 https://www.wikipedia.org
curl_chrome99 https://www.wikipedia.org
```

or run directly with you own flags:
```
curl-impersonate-ff https://www.wikipedia.org
curl-impersonate-chrome https://www.wikipedia.org
```

### macOS
*macOS support is still a work in progress and currently supports the Chrome version only.*

Install dependencies for building all the components:
```
brew install pkg-config make cmake ninja autoconf automake libtool
# For the Chrome version only
brew install go
```

Generate the configure script:
```
autoconf
```

Configure and compile:
```
mkdir build && cd build
../configure
# Build and install the Chrome version
gmake chrome-build
sudo gmake chrome-install
# Optionally remove all the build files
cd ../ && rm -Rf build
```

### Static compilation
To compile curl-impersonate statically with libcurl-impersonate, pass `--enable-static` to the `configure` script.

## Docker build
The Docker build is a bit more reproducible and serves as the reference implementation. It creates a Debian-based Docker image with the binaries.

### Chrome version
[`chrome/Dockerfile`](chrome/Dockerfile) is a debian-based Dockerfile that will build curl with all the necessary modifications and patches. Build it like the following:
```
docker build -t curl-impersonate-chrome chrome/
```
The resulting image contains a `/build/out` directory with the following:
* `curl-impersonate-chrome`, `curl-impersonate` - The curl binary that can impersonate Chrome/Edge/Safari. It is compiled statically against libcurl, BoringSSL, and libnghttp2 so that it won't conflict with any existing libraries on your system. You can use it from the container or copy it out. Tested to work on Ubuntu 20.04.
* `curl_chrome98`, `curl_chrome99`, `...` - Wrapper scripts that launch `curl-impersonate` with all the needed flags.
* `libcurl-impersonate-chrome.so`, `libcurl-impersonate.so` - libcurl compiled with impersonation support. See [libcurl-impersonate](#libcurl-impersonate) below for more details.

You can use them inside the docker, copy them out using `docker cp` or use them in a multi-stage docker build.

### Firefox version
Build with:
```
docker build -t curl-impersonate-ff firefox/
```
The resulting image contains a `/build/out` directory with the following:
* `curl-impersonate-ff`, `curl-impersonate` - The curl binary that can impersonate Firefox. It is compiled statically against libcurl, nss, and libnghttp2 so that it won't conflict with any existing libraries on your system. You can use it from the container or copy it out. Tested to work on Ubuntu 20.04.
* `curl_ff91esr`, `curl_ff95`, `...` - Wrapper scripts that launch `curl-impersonate` with all the needed flags.
* `libcurl-impersonate-ff.so`, `libcurl-impersonate.so` - libcurl compiled with impersonation support. See [libcurl-impersonate](#libcurl-impersonate) below for more details.

If you use it outside the container, install the following dependency:
* `sudo apt install libnss3`.  Even though nss is statically compiled into `curl-impersonate`, it is still necessary to install libnss3 because curl dynamically loads `libnssckbi.so`, a file containing Mozilla's list of trusted root certificates. Alternatively, use `curl -k` to disable certificate verification.
