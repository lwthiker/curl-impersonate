cmake_minimum_required(VERSION 3.20)
if(POLICY CMP0135)
  cmake_policy(SET CMP0135 NEW)
endif()

project(curl_impersonate_superbuild LANGUAGES C CXX)

include(ExternalProject)
include(GNUInstallDirs)
include(ProcessorCount)

find_program(_gmake_exe gmake)
if(_gmake_exe)
  set(AUTOTOOLS_MAKE "${_gmake_exe}")
else()
  set(AUTOTOOLS_MAKE "make")
endif()

ProcessorCount(_nproc)
if(NOT _nproc)
  set(_nproc 4)
endif()
set(SUBJOBS "${_nproc}" CACHE STRING "Parallel build jobs")

# Versions and URLs
set(BROTLI_VERSION "1.2.1")
set(BROTLI_URL_HASH "SHA256=98d35d11a78dc453aebb7d10c3748f3f73ff78c8267c0dc697b8631f67bf7e8f")
# Chrome 150
set(BORINGSSL_COMMIT "156c7b75ae9b8c3b3f847acf264f17594c3859fb")
set(BORINGSSL_URL_HASH "SHA256=450e169b284697c6eafe523cb7679f4221fbe1a0993f773a566c33b188762844")
# We need to pin to 1.64 or lower, since the priority flag was removed.
# See: https://nghttp2.org/blog/2025/03/02/nghttp2-v1-65-0/
set(NGHTTP2_VERSION "1.63.0")
set(NGHTTP2_URL_HASH "SHA256=607b174554d22a828bc532d1d734fe0f729b5d5ed207f2f12e96a62e83f29c55")
set(NGTCP2_VERSION "1.20.0")
set(NGTCP2_URL_HASH "SHA256=871ec97ad86803cf312901b0c393b0ee70163e25a87c9b2894d1234341ce4e97")
set(NGHTTP3_VERSION "1.15.0")
set(NGHTTP3_URL_HASH "SHA256=c6c491a52804814098e446630e6efc459afc0d3da7952ffe6cbdc0b3f99b2b62")
set(ZLIB_VERSION "1.3.2")
set(ZLIB_URL_HASH "SHA256=bb329a0a2cd0274d05519d61c667c062e06990d72e125ee2dfa8de64f0119d16")
set(ZSTD_VERSION "1.5.7")
set(ZSTD_URL_HASH "SHA256=eb33e51f49a15e023950cd7825ca74a4a2b43db8354825ac24fc1b7ee09e6fa3")
set(CARES_VERSION "1.34.9")
set(CARES_URL_HASH "SHA256=9364b70a12eb59a06830fb488d9357f90100dff0d98b23ea3593a183d43e6f2f")
set(CURL_VERSION "curl-8_23_0")
set(CURL_URL_HASH "SHA256=d0605d5883124ef5ae64c6d2b307e1417c482b362583b57491fdf37d9a99a792")

set(CURL_IMPERSONATE_VERSION "" CACHE STRING
  "Override the curl-impersonate version (defaults to an exact clean Git tag or local)")
set(_curl_impersonate_version "local")
if(CURL_IMPERSONATE_VERSION)
  set(_curl_impersonate_version "${CURL_IMPERSONATE_VERSION}")
else()
  find_package(Git QUIET)
  if(GIT_FOUND)
    execute_process(
      COMMAND "${GIT_EXECUTABLE}" status --porcelain --untracked-files=normal
      WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
      RESULT_VARIABLE _git_status_result
      OUTPUT_VARIABLE _git_status
      OUTPUT_STRIP_TRAILING_WHITESPACE
      ERROR_QUIET
    )
    execute_process(
      COMMAND "${GIT_EXECUTABLE}" describe --tags --exact-match HEAD
      WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
      RESULT_VARIABLE _git_tag_result
      OUTPUT_VARIABLE _git_tag
      OUTPUT_STRIP_TRAILING_WHITESPACE
      ERROR_QUIET
    )
    if(_git_status_result EQUAL 0 AND _git_status STREQUAL "" AND
       _git_tag_result EQUAL 0 AND NOT _git_tag STREQUAL "")
      string(REGEX REPLACE "^v" "" _curl_impersonate_version "${_git_tag}")
    endif()
  endif()
endif()
message(STATUS "curl-impersonate version: ${_curl_impersonate_version}")

set(ZLIB_URL "https://github.com/madler/zlib/releases/download/v${ZLIB_VERSION}/zlib-${ZLIB_VERSION}.tar.gz")
set(ZSTD_URL "https://github.com/facebook/zstd/releases/download/v${ZSTD_VERSION}/zstd-${ZSTD_VERSION}.tar.gz")
set(BROTLI_URL "https://github.com/google/brotli/archive/refs/tags/v${BROTLI_VERSION}.tar.gz")
set(BORINGSSL_URL "https://github.com/google/boringssl/archive/${BORINGSSL_COMMIT}.zip")
set(NGHTTP2_URL "https://github.com/nghttp2/nghttp2/releases/download/v${NGHTTP2_VERSION}/nghttp2-${NGHTTP2_VERSION}.tar.bz2")
set(NGTCP2_URL "https://github.com/ngtcp2/ngtcp2/releases/download/v${NGTCP2_VERSION}/ngtcp2-${NGTCP2_VERSION}.tar.bz2")
set(NGHTTP3_URL "https://github.com/ngtcp2/nghttp3/releases/download/v${NGHTTP3_VERSION}/nghttp3-${NGHTTP3_VERSION}.tar.bz2")
set(CARES_URL "https://github.com/c-ares/c-ares/releases/download/v${CARES_VERSION}/c-ares-${CARES_VERSION}.tar.gz")
set(CURL_URL "https://github.com/curl/curl/archive/${CURL_VERSION}.tar.gz")

set(_disable_boringssl_asm_default OFF)
if(WIN32)
  string(TOLOWER "${CMAKE_SYSTEM_PROCESSOR}" _ci_system_processor_lc)
  string(TOLOWER "${CMAKE_C_COMPILER_TARGET}" _ci_c_target_lc)
  string(TOLOWER "${CMAKE_CXX_COMPILER_TARGET}" _ci_cxx_target_lc)
  string(TOLOWER "${CMAKE_GENERATOR_PLATFORM}" _ci_generator_platform_lc)
  if(MSVC OR (CMAKE_C_COMPILER_FRONTEND_VARIANT STREQUAL "MSVC"
      OR CMAKE_CXX_COMPILER_FRONTEND_VARIANT STREQUAL "MSVC"))
    if(_ci_system_processor_lc MATCHES "arm64|aarch64"
        OR _ci_c_target_lc MATCHES "arm64|aarch64"
        OR _ci_cxx_target_lc MATCHES "arm64|aarch64"
        OR _ci_generator_platform_lc MATCHES "arm64")
      set(_disable_boringssl_asm_default ON)
    endif()
  elseif(MINGW)
    if(_ci_system_processor_lc MATCHES "^arm$|armv7"
        OR _ci_c_target_lc MATCHES "^arm$|armv7"
        OR _ci_cxx_target_lc MATCHES "^arm$|armv7")
      set(_disable_boringssl_asm_default ON)
    endif()
  endif()
endif()
option(DISABLE_BORINGSSL_ASM "Disable BoringSSL asm (arm64 workaround)" ${_disable_boringssl_asm_default})
if(WIN32 OR APPLE OR ANDROID OR CMAKE_SYSTEM_NAME MATCHES "BSD$")
  set(_use_libidn2_default OFF)
else()
  set(_use_libidn2_default ON)
endif()
option(USE_LIBIDN2 "Build and use libidn2/libunistring for IDN support" ${_use_libidn2_default})
option(CURL_SUBPROJECT_FORCE_OPENSSL_PATHS
  "Pass explicit OPENSSL_* paths to the curl subproject"
  ON)
set(CURL_CA_BUNDLE "" CACHE STRING "CA bundle for curl ('auto', 'none', or full path)")
set(CURL_CA_PATH "" CACHE STRING "CA directory for curl ('auto', 'none', or full path)")

set(DEPS_SRC_DIR "${CMAKE_BINARY_DIR}/deps/src")
set(DEPS_BUILD_DIR "${CMAKE_BINARY_DIR}/deps/build")
set(DEPS_INSTALL_DIR "${CMAKE_BINARY_DIR}/deps/install")

if(WIN32)
  find_program(PATCH_EXE patch
    HINTS
      "$ENV{ProgramFiles}/Git/usr/bin"
      "$ENV{ProgramW6432}/Git/usr/bin"
      "C:/Program Files/Git/usr/bin"
      "C:/Program Files (x86)/Git/usr/bin"
  )
else()
  find_program(PATCH_EXE NAMES gpatch patch)
endif()
if(NOT PATCH_EXE)
  set(PATCH_EXE patch)
endif()

function(_invalidate_external_project project reason)
  message(STATUS "${reason}; invalidating the ${project} external project")
  file(REMOVE_RECURSE
    "${CMAKE_BINARY_DIR}/${project}-prefix/src/${project}-stamp"
    "${DEPS_SRC_DIR}/${project}"
    "${DEPS_BUILD_DIR}/${project}"
  )
endfunction()

function(_track_external_project_patch project patch_file_var patch_changed_var)
  set(_patch_file "${CMAKE_SOURCE_DIR}/patches/${project}.patch")
  set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
    "${_patch_file}"
  )

  set(_patch_changed OFF)
  set(_patch_stamp
    "${CMAKE_BINARY_DIR}/${project}-prefix/src/${project}-stamp/${project}-patch"
  )
  if(EXISTS "${_patch_stamp}" AND
     "${_patch_file}" IS_NEWER_THAN "${_patch_stamp}")
    set(_patch_changed ON)
    _invalidate_external_project("${project}" "${project}.patch changed")
  endif()

  set(${patch_file_var} "${_patch_file}" PARENT_SCOPE)
  set(${patch_changed_var} "${_patch_changed}" PARENT_SCOPE)
endfunction()

set(_toolchain_cmake_args)
if(CMAKE_C_COMPILER)
  list(APPEND _toolchain_cmake_args "-DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}")
endif()
if(CMAKE_CXX_COMPILER)
  list(APPEND _toolchain_cmake_args "-DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}")
endif()
if(CMAKE_CROSSCOMPILING AND CMAKE_SYSTEM_NAME)
  list(APPEND _toolchain_cmake_args "-DCMAKE_SYSTEM_NAME=${CMAKE_SYSTEM_NAME}")
endif()
if(CMAKE_SYSTEM_PROCESSOR)
  list(APPEND _toolchain_cmake_args "-DCMAKE_SYSTEM_PROCESSOR=${CMAKE_SYSTEM_PROCESSOR}")
endif()
if(CMAKE_OSX_SYSROOT)
  list(APPEND _toolchain_cmake_args "-DCMAKE_OSX_SYSROOT=${CMAKE_OSX_SYSROOT}")
endif()
if(CMAKE_OSX_DEPLOYMENT_TARGET)
  list(APPEND _toolchain_cmake_args "-DCMAKE_OSX_DEPLOYMENT_TARGET=${CMAKE_OSX_DEPLOYMENT_TARGET}")
endif()
if(CMAKE_MSVC_RUNTIME_LIBRARY)
  list(APPEND _toolchain_cmake_args
    "-DCMAKE_MSVC_RUNTIME_LIBRARY=${CMAKE_MSVC_RUNTIME_LIBRARY}"
    "-DCMAKE_POLICY_DEFAULT_CMP0091=NEW"
  )
endif()
if(MINGW)
  list(APPEND _toolchain_cmake_args
    "-DCMAKE_EXE_LINKER_FLAGS=-static"
    "-DCMAKE_SHARED_LINKER_FLAGS=-static"
  )
endif()
if(CMAKE_LINKER)
  list(APPEND _toolchain_cmake_args "-DCMAKE_LINKER=${CMAKE_LINKER}")
endif()
if(ANDROID)
  list(APPEND _toolchain_cmake_args
    "-DCMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE}"
    "-DCMAKE_ANDROID_NDK=${CMAKE_ANDROID_NDK}"
    "-DANDROID_ABI=${ANDROID_ABI}"
    "-DANDROID_PLATFORM=${ANDROID_PLATFORM}"
    "-DCMAKE_ANDROID_ARCH_ABI=${CMAKE_ANDROID_ARCH_ABI}"
    "-DCMAKE_SYSTEM_VERSION=${CMAKE_SYSTEM_VERSION}"
    "-DANDROID_PLATFORM_LEVEL=${CMAKE_SYSTEM_VERSION}"
  )
endif()

set(_common_cmake_args
  -DCMAKE_BUILD_TYPE=Release
  -DCMAKE_INSTALL_LIBDIR=lib
  -DCMAKE_POSITION_INDEPENDENT_CODE=ON
  ${_toolchain_cmake_args}
)

# Avoid include shadowing from system/local prefixes when building deps:
# force CMake "SYSTEM" include dirs to be passed as -I, and avoid imported
# targets being marked as system includes.
set(_shadow_avoid_cmake_args
  -DCMAKE_NO_SYSTEM_FROM_IMPORTED=ON
  -DCMAKE_INCLUDE_SYSTEM_FLAG_C=-I
)

list(JOIN _common_cmake_args " " _common_cmake_args_str)

# c-ares
set(_cares_platform_args)
if(APPLE)
  # New Apple SDKs expose pipe2 even for deployment targets that lack it.
  # Use c-ares's portable pipe/fcntl fallback.
  list(APPEND _cares_platform_args -DHAVE_PIPE2=OFF)
endif()
ExternalProject_Add(cares
  URL "${CARES_URL}"
  URL_HASH "${CARES_URL_HASH}"
  SOURCE_DIR "${DEPS_SRC_DIR}/cares"
  BINARY_DIR "${DEPS_BUILD_DIR}/cares"
  INSTALL_DIR "${DEPS_INSTALL_DIR}"
  CMAKE_ARGS
    ${_common_cmake_args}
    -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR>
    ${_cares_platform_args}
    -DCARES_SHARED=OFF
    -DCARES_STATIC=ON
    -DCARES_STATIC_PIC=ON
    -DCARES_BUILD_TOOLS=OFF
    -DCARES_BUILD_TESTS=OFF
  BUILD_COMMAND ${CMAKE_COMMAND} --build <BINARY_DIR> --config Release --parallel ${SUBJOBS}
  INSTALL_COMMAND ${CMAKE_COMMAND} --build <BINARY_DIR> --config Release --target install --parallel ${SUBJOBS}
)

# zlib
ExternalProject_Add(zlib
  URL "${ZLIB_URL}"
  URL_HASH "${ZLIB_URL_HASH}"
  SOURCE_DIR "${DEPS_SRC_DIR}/zlib"
  BINARY_DIR "${DEPS_BUILD_DIR}/zlib"
  INSTALL_DIR "${DEPS_INSTALL_DIR}"
  CMAKE_ARGS
    ${_common_cmake_args}
    -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR>
    -DZLIB_BUILD_SHARED=OFF
    -DZLIB_BUILD_TESTING=OFF
  BUILD_COMMAND ${CMAKE_COMMAND} --build <BINARY_DIR> --config Release --parallel ${SUBJOBS}
)

# zstd
ExternalProject_Add(zstd
  URL "${ZSTD_URL}"
  URL_HASH "${ZSTD_URL_HASH}"
  SOURCE_DIR "${DEPS_SRC_DIR}/zstd"
  BINARY_DIR "${DEPS_BUILD_DIR}/zstd"
  INSTALL_DIR "${DEPS_INSTALL_DIR}"
  SOURCE_SUBDIR build/cmake
  CMAKE_ARGS
    ${_common_cmake_args}
    -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR>
    -DZSTD_BUILD_SHARED=OFF
    -DZSTD_BUILD_STATIC=ON
    -DZSTD_BUILD_PROGRAMS=OFF
    -DZSTD_BUILD_CONTRIB=OFF
    -DZSTD_BUILD_TESTS=OFF
  BUILD_COMMAND ${CMAKE_COMMAND} --build <BINARY_DIR> --config Release --parallel ${SUBJOBS}
)

# brotli
_track_external_project_patch(brotli _brotli_patch_file _brotli_patch_changed)
ExternalProject_Add(brotli
  URL "${BROTLI_URL}"
  URL_HASH "${BROTLI_URL_HASH}"
  SOURCE_DIR "${DEPS_SRC_DIR}/brotli"
  BINARY_DIR "${DEPS_BUILD_DIR}/brotli"
  INSTALL_DIR "${DEPS_INSTALL_DIR}"
  PATCH_COMMAND ${PATCH_EXE} -p1 -i "${_brotli_patch_file}"
  CMAKE_ARGS
    ${_common_cmake_args}
    -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR>
    -DBUILD_SHARED_LIBS=OFF
    -DBROTLI_DISABLE_TESTS=ON
    -DBROTLI_DISABLE_TOOLS=ON
    -DBROTLI_BUILD_TOOLS=OFF
    -DCMAKE_MACOSX_BUNDLE=OFF
  BUILD_COMMAND ${CMAKE_COMMAND} --build <BINARY_DIR> --config Release --parallel ${SUBJOBS}
  INSTALL_COMMAND ${CMAKE_COMMAND} --build <BINARY_DIR> --config Release --target install --parallel ${SUBJOBS}
)

# boringssl

# The extra CMAKE_C_FLAGS are needed because otherwise boringssl fails to
# compile in release mode on some systems with gcc 12 (e.g. Fedora).
# In addition, guard these options with -Wno-unknown-warning-option to
# prevent clang from failing on them.
set(_boringssl_c_flags "${CMAKE_C_FLAGS}")
string(APPEND _boringssl_c_flags " -Wno-unknown-warning-option -Wno-stringop-overflow -Wno-array-bounds -Wno-macro-redefined")
set(_boringssl_cxx_flags "${CMAKE_CXX_FLAGS}")
string(APPEND _boringssl_cxx_flags " -Wno-macro-redefined")

set(_boringssl_cmake_args
  ${_common_cmake_args}
  "-DCMAKE_C_FLAGS=${_boringssl_c_flags}"
  "-DCMAKE_CXX_FLAGS=${_boringssl_cxx_flags}"
  -DCMAKE_INSTALL_PREFIX=${DEPS_INSTALL_DIR}
  -DBUILD_TESTING=OFF
)
if(DISABLE_BORINGSSL_ASM)
  list(APPEND _boringssl_cmake_args -DOPENSSL_NO_ASM=ON)
endif()
if(CMAKE_ASM_NASM_COMPILER)
  list(APPEND _boringssl_cmake_args "-DCMAKE_ASM_NASM_COMPILER=${CMAKE_ASM_NASM_COMPILER}")
endif()

_track_external_project_patch(
  boringssl _boringssl_patch_file _boringssl_patch_changed
)
ExternalProject_Add(boringssl
  URL "${BORINGSSL_URL}"
  URL_HASH "${BORINGSSL_URL_HASH}"
  SOURCE_DIR "${DEPS_SRC_DIR}/boringssl"
  BINARY_DIR "${DEPS_BUILD_DIR}/boringssl"
  PATCH_COMMAND ${PATCH_EXE} -p1 -i "${_boringssl_patch_file}"
  CMAKE_ARGS ${_boringssl_cmake_args}
  BUILD_COMMAND ${CMAKE_COMMAND} --build <BINARY_DIR> --config Release --target ssl crypto --parallel ${SUBJOBS}
  INSTALL_COMMAND ${CMAKE_COMMAND} --build <BINARY_DIR> --config Release --target install --parallel ${SUBJOBS}
)

ExternalProject_Get_Property(boringssl source_dir binary_dir)
set(BORINGSSL_SRC_DIR "${source_dir}")
set(BORINGSSL_BIN_DIR "${binary_dir}")
if(MSVC OR (CMAKE_C_COMPILER_FRONTEND_VARIANT STREQUAL "MSVC"
    OR CMAKE_CXX_COMPILER_FRONTEND_VARIANT STREQUAL "MSVC"))
  set(BORINGSSL_SSL_LIB "${DEPS_INSTALL_DIR}/lib/ssl.lib")
  set(BORINGSSL_CRYPTO_LIB "${DEPS_INSTALL_DIR}/lib/crypto.lib")
else()
  set(BORINGSSL_SSL_LIB "${DEPS_INSTALL_DIR}/lib/libssl.a")
  set(BORINGSSL_CRYPTO_LIB "${DEPS_INSTALL_DIR}/lib/libcrypto.a")
endif()
set(BORINGSSL_INCLUDE_DIR "${BORINGSSL_SRC_DIR}/include")

set(_ngtcp2_boringssl_libs_arg)
if(MSVC OR (CMAKE_C_COMPILER_FRONTEND_VARIANT STREQUAL "MSVC"
    OR CMAKE_CXX_COMPILER_FRONTEND_VARIANT STREQUAL "MSVC"))
  list(APPEND _ngtcp2_boringssl_libs_arg "-DBORINGSSL_LIBRARIES=${BORINGSSL_SSL_LIB}|${BORINGSSL_CRYPTO_LIB}")
endif()

# nghttp2
ExternalProject_Add(nghttp2
  URL "${NGHTTP2_URL}"
  URL_HASH "${NGHTTP2_URL_HASH}"
  SOURCE_DIR "${DEPS_SRC_DIR}/nghttp2"
  BINARY_DIR "${DEPS_BUILD_DIR}/nghttp2"
  INSTALL_DIR "${DEPS_INSTALL_DIR}"
  CMAKE_ARGS
    ${_common_cmake_args}
    ${_shadow_avoid_cmake_args}
    -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR>
    -DCMAKE_DISABLE_FIND_PACKAGE_Libnghttp3=ON
    -DENABLE_LIB_ONLY=ON
    -DBUILD_SHARED_LIBS=OFF
    -DBUILD_STATIC_LIBS=ON
    -DENABLE_DOC=OFF
    -DBUILD_TESTING=OFF
  BUILD_COMMAND ${CMAKE_COMMAND} --build <BINARY_DIR> --config Release --parallel ${SUBJOBS}
  INSTALL_COMMAND ${CMAKE_COMMAND} --build <BINARY_DIR> --config Release --target install --parallel ${SUBJOBS}
)

# nghttp3
_track_external_project_patch(nghttp3 _nghttp3_patch_file _nghttp3_patch_changed)
ExternalProject_Add(nghttp3
  URL "${NGHTTP3_URL}"
  URL_HASH "${NGHTTP3_URL_HASH}"
  SOURCE_DIR "${DEPS_SRC_DIR}/nghttp3"
  BINARY_DIR "${DEPS_BUILD_DIR}/nghttp3"
  INSTALL_DIR "${DEPS_INSTALL_DIR}"
  PATCH_COMMAND ${PATCH_EXE} -p1 -i "${_nghttp3_patch_file}"
  CMAKE_ARGS
    ${_common_cmake_args}
    ${_shadow_avoid_cmake_args}
    -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR>
    -DENABLE_LIB_ONLY=ON
    -DENABLE_SHARED_LIB=OFF
    -DENABLE_STATIC_LIB=ON
    -DBUILD_TESTING=OFF
  BUILD_COMMAND ${CMAKE_COMMAND} --build <BINARY_DIR> --config Release --parallel ${SUBJOBS}
  INSTALL_COMMAND
    ${CMAKE_COMMAND} --build <BINARY_DIR> --config Release --target install --parallel ${SUBJOBS}
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
      <SOURCE_DIR>/lib/includes/nghttp3/nghttp3.h
      <INSTALL_DIR>/include/nghttp3/nghttp3.h
    COMMAND ${CMAKE_COMMAND}
      -DHEADER=<INSTALL_DIR>/include/nghttp3/nghttp3.h
      -DNEEDLE=nghttp3_settings_entry
      -P "${CMAKE_SOURCE_DIR}/cmake/CheckFileContains.cmake"
)

# ngtcp2
_track_external_project_patch(ngtcp2 _ngtcp2_patch_file _ngtcp2_patch_changed)
if(_boringssl_patch_changed)
  _invalidate_external_project(ngtcp2 "boringssl.patch changed")
endif()
ExternalProject_Add(ngtcp2
  LIST_SEPARATOR |
  URL "${NGTCP2_URL}"
  URL_HASH "${NGTCP2_URL_HASH}"
  SOURCE_DIR "${DEPS_SRC_DIR}/ngtcp2"
  BINARY_DIR "${DEPS_BUILD_DIR}/ngtcp2"
  INSTALL_DIR "${DEPS_INSTALL_DIR}"
  PATCH_COMMAND ${PATCH_EXE} -p1 -i "${_ngtcp2_patch_file}"
  DEPENDS boringssl
  CMAKE_ARGS
    ${_common_cmake_args}
    ${_shadow_avoid_cmake_args}
    -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR>
    -DENABLE_SHARED_LIB=OFF
    -DENABLE_STATIC_LIB=ON
    -DENABLE_LIB_ONLY=ON
    -DENABLE_OPENSSL=OFF
    -DENABLE_BORINGSSL=ON
    -DENABLE_PICOTLS=OFF
    -DENABLE_WOLFSSL=OFF
    -DENABLE_GNUTLS=OFF
    -DBUILD_TESTING=OFF
    -DBORINGSSL_INCLUDE_DIR=${BORINGSSL_INCLUDE_DIR}
    ${_ngtcp2_boringssl_libs_arg}
  BUILD_COMMAND ${CMAKE_COMMAND} --build <BINARY_DIR> --config Release --parallel ${SUBJOBS}
  INSTALL_COMMAND ${CMAKE_COMMAND} --build <BINARY_DIR> --config Release --target install --parallel ${SUBJOBS}
)

# libidn2
if(USE_LIBIDN2)
  set(_libidn2_archive "${DEPS_INSTALL_DIR}/lib/libidn2.a")
  if(NOT EXISTS "${_libidn2_archive}")
    message(FATAL_ERROR
      "USE_LIBIDN2 requires prebuilt libidn2 in ${DEPS_INSTALL_DIR}. "
      "Run `make prepare-libidn2` before configuring CMake, or use "
      "`make configure` so the Autotools IDN preparation runs first.")
  endif()
  add_custom_target(libidn2
    COMMAND ${CMAKE_COMMAND} -E echo "Using prebuilt libidn2 from ${DEPS_INSTALL_DIR}"
  )
endif()

# curl
# FindOpenSSL queries pkg-config independently of CURL_USE_PKGCONFIG. Keep the
# module available for older CMake versions, but restrict it to staged metadata.
set(_curl_use_pkgconfig_flag
  -DCURL_USE_PKGCONFIG=OFF
  -DCMAKE_DISABLE_FIND_PACKAGE_PkgConfig=OFF
  -DPKG_CONFIG_USE_CMAKE_PREFIX_PATH=OFF
)
set(_curl_clean_env)
if(NOT WIN32)
  list(APPEND _curl_clean_env
    "CPATH="
    "C_INCLUDE_PATH="
    "CPLUS_INCLUDE_PATH="
    "LIBRARY_PATH="
    "PKG_CONFIG_PATH="
    "PKG_CONFIG_LIBDIR=${DEPS_INSTALL_DIR}/lib/pkgconfig"
  )
endif()

if(WIN32)
  set(_curl_idn_flags -DUSE_WIN32_IDN=ON -DUSE_LIBIDN2=OFF)
elseif(APPLE)
  if(USE_LIBIDN2)
    set(_curl_idn_flags -DUSE_APPLE_IDN=OFF -DUSE_LIBIDN2=ON)
  else()
    set(_curl_idn_flags -DUSE_APPLE_IDN=ON -DUSE_LIBIDN2=OFF)
  endif()
elseif(ANDROID)
  set(_curl_idn_flags -DUSE_LIBIDN2=OFF)
elseif(USE_LIBIDN2)
  set(_curl_idn_flags -DUSE_LIBIDN2=ON)
else()
  set(_curl_idn_flags -DUSE_LIBIDN2=OFF)
endif()

# Single curl build mode: produce shared+static libcurl and static curl binary.
set(_curl_build_flags
  -DBUILD_SHARED_LIBS=ON
  -DBUILD_STATIC_LIBS=ON
  -DBUILD_STATIC_CURL=ON
  -DBUILD_CURL_EXE=ON
)

set(_curl_ca_flags)
if(NOT CURL_CA_BUNDLE STREQUAL "")
  list(APPEND _curl_ca_flags "-DCURL_CA_BUNDLE=${CURL_CA_BUNDLE}")
endif()
if(NOT CURL_CA_PATH STREQUAL "")
  list(APPEND _curl_ca_flags "-DCURL_CA_PATH=${CURL_CA_PATH}")
endif()

set(_curl_deps zlib zstd brotli boringssl nghttp2 ngtcp2 nghttp3)

if(ANDROID)
  set(_curl_resolver_flags
    -DENABLE_ARES=OFF
    -DENABLE_THREADED_RESOLVER=ON
  )
else()
  list(APPEND _curl_deps cares)
  set(_curl_resolver_flags
    -DENABLE_ARES=ON
    -DENABLE_THREADED_RESOLVER=OFF
    -DCARES_USE_STATIC_LIBS=ON
    -DCURL_USE_CMAKECONFIG=ON
    "-Dc-ares_DIR=${DEPS_INSTALL_DIR}/lib/cmake/c-ares"
  )
endif()
if(USE_LIBIDN2)
  list(APPEND _curl_deps libidn2)
endif()

if(MSVC OR (CMAKE_C_COMPILER_FRONTEND_VARIANT STREQUAL "MSVC"
    OR CMAKE_CXX_COMPILER_FRONTEND_VARIANT STREQUAL "MSVC"))
  set(_curl_zlib_library "${DEPS_INSTALL_DIR}/lib/zs.lib")
  set(_curl_zstd_library "${DEPS_INSTALL_DIR}/lib/zstd_static.lib")
elseif(MINGW)
  set(_curl_zlib_library "${DEPS_INSTALL_DIR}/lib/libzs.a")
  set(_curl_zstd_library "${DEPS_INSTALL_DIR}/lib/libzstd.a")
else()
  set(_curl_zlib_library "${DEPS_INSTALL_DIR}/lib/libz.a")
  set(_curl_zstd_library "${DEPS_INSTALL_DIR}/lib/libzstd.a")
endif()

set(_curl_staged_dependency_args
  "-DCMAKE_PREFIX_PATH=${DEPS_INSTALL_DIR}"
)
if(NOT (MSVC OR (CMAKE_C_COMPILER_FRONTEND_VARIANT STREQUAL "MSVC"
      OR CMAKE_CXX_COMPILER_FRONTEND_VARIANT STREQUAL "MSVC")))
  set(_curl_c_flags "${CMAKE_C_FLAGS}")
  set(_curl_cxx_flags "${CMAKE_CXX_FLAGS}")
  string(PREPEND _curl_c_flags "-I${DEPS_INSTALL_DIR}/include ")
  string(PREPEND _curl_cxx_flags "-I${DEPS_INSTALL_DIR}/include ")
  string(STRIP "${_curl_c_flags}" _curl_c_flags)
  string(STRIP "${_curl_cxx_flags}" _curl_cxx_flags)

  list(APPEND _curl_staged_dependency_args
    "-DCMAKE_C_FLAGS=${_curl_c_flags}"
    "-DCMAKE_CXX_FLAGS=${_curl_cxx_flags}"
    "-DBROTLI_INCLUDE_DIR=${DEPS_INSTALL_DIR}/include"
    "-DBROTLIDEC_LIBRARY=${DEPS_INSTALL_DIR}/lib/libbrotlidec.a"
    "-DBROTLICOMMON_LIBRARY=${DEPS_INSTALL_DIR}/lib/libbrotlicommon.a"
    "-DNGHTTP2_INCLUDE_DIR=${DEPS_INSTALL_DIR}/include"
    "-DNGHTTP2_LIBRARY=${DEPS_INSTALL_DIR}/lib/libnghttp2.a"
    "-DNGHTTP3_INCLUDE_DIR=${DEPS_INSTALL_DIR}/include"
    "-DNGHTTP3_LIBRARY=${DEPS_INSTALL_DIR}/lib/libnghttp3.a"
    "-DNGTCP2_INCLUDE_DIR=${DEPS_INSTALL_DIR}/include"
    "-DNGTCP2_LIBRARY=${DEPS_INSTALL_DIR}/lib/libngtcp2.a"
    "-DNGTCP2_CRYPTO_BORINGSSL_LIBRARY=${DEPS_INSTALL_DIR}/lib/libngtcp2_crypto_boringssl.a"
  )
endif()
if(APPLE)
  list(APPEND _curl_staged_dependency_args
    "-DCMAKE_IGNORE_PREFIX_PATH=/usr/local|/opt/homebrew"
    "-DCMAKE_IGNORE_PATH=/usr/local/include|/usr/local/lib|/opt/homebrew/include|/opt/homebrew/lib"
  )
endif()
if(USE_LIBIDN2 AND NOT WIN32)
  # The prebuild makes libidn2 self-contained with its included libunistring.
  list(APPEND _curl_staged_dependency_args
    "-DLIBIDN2_INCLUDE_DIR=${DEPS_INSTALL_DIR}/include"
    "-DLIBIDN2_LIBRARY=${DEPS_INSTALL_DIR}/lib/libidn2.a"
  )
endif()

set(_curl_platform_flags)
if(WIN32)
  list(APPEND _curl_platform_flags -DENABLE_UNICODE=ON -DCURL_CA_NATIVE=ON)
endif()
if(MSVC OR (CMAKE_C_COMPILER_FRONTEND_VARIANT STREQUAL "MSVC"
    OR CMAKE_CXX_COMPILER_FRONTEND_VARIANT STREQUAL "MSVC"))
  set(_curl_platform_c_flags "${CMAKE_C_FLAGS}")
  string(APPEND _curl_platform_c_flags " /DNGHTTP2_STATICLIB=1 /DNGTCP2_STATICLIB=1 /DNGHTTP3_STATICLIB=1 /Dstrtok_r=strtok_s")
  list(APPEND _curl_platform_flags "-DCMAKE_C_FLAGS=${_curl_platform_c_flags}")
  if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    list(APPEND _curl_platform_flags "-Dssize_t=__int64")
  else()
    list(APPEND _curl_platform_flags "-Dssize_t=long")
  endif()
elseif(MINGW)
  set(_curl_platform_c_flags "${CMAKE_C_FLAGS}")
  string(APPEND _curl_platform_c_flags " -DNGHTTP2_STATICLIB=1 -DNGTCP2_STATICLIB=1 -DNGHTTP3_STATICLIB=1")
  list(APPEND _curl_platform_flags "-DCMAKE_C_FLAGS=${_curl_platform_c_flags}")
elseif(APPLE)
  list(APPEND _curl_platform_flags -DUSE_APPLE_SECTRUST=ON)
endif()
if(CMAKE_MSVC_RUNTIME_LIBRARY)
  list(APPEND _curl_platform_flags "-DCMAKE_MSVC_RUNTIME_LIBRARY=${CMAKE_MSVC_RUNTIME_LIBRARY}")
endif()

set(_curl_openssl_flags)
if(CURL_SUBPROJECT_FORCE_OPENSSL_PATHS)
  list(APPEND _curl_openssl_flags
    -DOPENSSL_ROOT_DIR=${DEPS_INSTALL_DIR}
    -DOPENSSL_INCLUDE_DIR=${BORINGSSL_INCLUDE_DIR}
    -DOPENSSL_SSL_LIBRARY=${BORINGSSL_SSL_LIB}
    -DOPENSSL_CRYPTO_LIBRARY=${BORINGSSL_CRYPTO_LIB}
    -DOPENSSL_USE_STATIC_LIBS=ON
    -DHAVE_BORINGSSL=1
    -DHAVE_AWSLC=0
    -DHAVE_LIBRESSL=0
  )
endif()

_track_external_project_patch(curl _curl_patch_file _curl_patch_changed)
if(NOT _curl_patch_changed AND
   (_brotli_patch_changed OR _boringssl_patch_changed OR
    _nghttp3_patch_changed OR _ngtcp2_patch_changed))
  _invalidate_external_project(curl "A curl dependency patch changed")
endif()

ExternalProject_Add(curl
  LIST_SEPARATOR |
  URL "${CURL_URL}"
  URL_HASH "${CURL_URL_HASH}"
  SOURCE_DIR "${DEPS_SRC_DIR}/curl"
  BINARY_DIR "${DEPS_BUILD_DIR}/curl"
  INSTALL_DIR "${CMAKE_INSTALL_PREFIX}"
  PATCH_COMMAND ${PATCH_EXE} -p1 -i "${_curl_patch_file}"
  DEPENDS ${_curl_deps}
  CONFIGURE_COMMAND
    ${CMAKE_COMMAND} -E env
      ${_curl_clean_env}
    ${CMAKE_COMMAND}
      # Remove host OpenSSL metadata cached by earlier configurations.
      -U_OPENSSL_*
      -DCMAKE_BUILD_TYPE=Release
      ${_shadow_avoid_cmake_args}
      -DCMAKE_INSTALL_PREFIX=${CMAKE_INSTALL_PREFIX}
      -DCMAKE_INSTALL_LIBDIR=${CMAKE_INSTALL_LIBDIR}
      -DCMAKE_INSTALL_INCLUDEDIR=${CMAKE_INSTALL_INCLUDEDIR}
      -DCMAKE_INSTALL_BINDIR=${CMAKE_INSTALL_BINDIR}
      ${_toolchain_cmake_args}
      -DCMAKE_POSITION_INDEPENDENT_CODE=ON
      ${_curl_staged_dependency_args}
      ${_curl_use_pkgconfig_flag}
      -DCMAKE_PROJECT_CURL_INCLUDE=${CMAKE_SOURCE_DIR}/cmake/WebCrypto.cmake
      -DCURL_IMPERSONATE_SOURCE_DIR=${CMAKE_SOURCE_DIR}
      -DCURL_USE_OPENSSL=ON
      -DCURL_ENABLE_SSL=ON
      -DCURL_IMPERSONATE_VERSION=${_curl_impersonate_version}
      ${_curl_openssl_flags}
      # Bypass BoringSSL check
      -DHAVE_DES_ECB_ENCRYPT=1
      -DHAVE_SSL_SET0_WBIO=1
      -DHAVE_SSL_SET1_ECH_CONFIG_LIST=1
      -DHAVE_SSL_SET_QUIC_USE_LEGACY_CODEPOINT=1
      -DHAVE_OPENSSL_SRP=0
      -DCURL_BROTLI=ON
      -DCURL_ZSTD=ON
      # Make sure curl doesn't link against an unversioned .so (Linux only).
      -DZLIB_INCLUDE_DIR=${DEPS_INSTALL_DIR}/include
      -DZLIB_LIBRARY=${_curl_zlib_library}
      -DZLIB_LIBRARY_RELEASE=${_curl_zlib_library}
      -DZSTD_INCLUDE_DIR=${DEPS_INSTALL_DIR}/include
      -DZSTD_LIBRARY=${_curl_zstd_library}
      -DUSE_NGHTTP2=ON
      -DUSE_NGTCP2=ON
      -DUSE_PROXY_HTTP3=ON
      -DCURL_DISABLE_LDAP=ON
      -DCURL_DISABLE_LDAPS=ON
      # XXX: psl should be enabled in the future:
      # https://daniel.haxx.se/blog/2024/01/10/psl-in-curl/
      -DCURL_USE_LIBPSL=OFF
      -DUSE_LIBRTMP=OFF
      -DCURL_DISABLE_WEBSOCKETS=OFF
      -DUSE_ECH=ON
      -DUSE_SSLS_EXPORT=ON
      -DENABLE_IPV6=ON
      -DCURL_USE_LIBSSH2=OFF
      -DBUILD_MISC_DOCS=OFF
      -DENABLE_CURL_MANUAL=OFF
      ${_curl_resolver_flags}
      ${_curl_ca_flags}
      ${_curl_idn_flags}
      ${_curl_build_flags}
      ${_curl_platform_flags}
      -GNinja
      -S <SOURCE_DIR> -B <BINARY_DIR>
  BUILD_COMMAND
    ${CMAKE_COMMAND} -E env
      ${_curl_clean_env}
    ${CMAKE_COMMAND} --build <BINARY_DIR> --config Release --parallel ${SUBJOBS}
  INSTALL_COMMAND ""
)

add_custom_target(curl-impersonate ALL DEPENDS curl)

add_custom_target(curl-install
  DEPENDS curl
)

add_custom_target(install-all
  COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target curl-install
  COMMAND ${CMAKE_COMMAND} --install ${CMAKE_BINARY_DIR}
)

# Install runtime artifacts and the files needed by libcurl consumers.
# Do not call curl's own install target, which also installs docs/manpages.
if(WIN32)
  install(PROGRAMS "${DEPS_BUILD_DIR}/curl/src/curl-impersonate.exe" DESTINATION ${CMAKE_INSTALL_BINDIR})
elseif(CMAKE_SYSTEM_NAME STREQUAL "iOS")
  install(PROGRAMS "${DEPS_BUILD_DIR}/curl/src/curl-impersonate.app/curl-impersonate" DESTINATION ${CMAKE_INSTALL_BINDIR})
else()
  install(PROGRAMS "${DEPS_BUILD_DIR}/curl/src/curl-impersonate" DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()
if(WIN32)
  install(
    DIRECTORY "${DEPS_BUILD_DIR}/curl/lib/"
    DESTINATION ${CMAKE_INSTALL_LIBDIR}
    FILES_MATCHING
      PATTERN "CMakeFiles" EXCLUDE
      PATTERN "libcurl-impersonate*.lib"
      PATTERN "libcurl-impersonate*.a"
      PATTERN "libcurl-impersonate*.dll"
  )
else()
  install(
    DIRECTORY "${DEPS_BUILD_DIR}/curl/lib/"
    DESTINATION ${CMAKE_INSTALL_LIBDIR}
    FILES_MATCHING
      PATTERN "CMakeFiles" EXCLUDE
      PATTERN "libcurl-impersonate*.a"
      PATTERN "libcurl-impersonate*.so*"
      PATTERN "libcurl-impersonate*.dylib*"
  )
endif()
install(
  DIRECTORY "${DEPS_SRC_DIR}/curl/include/curl"
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
  FILES_MATCHING
    PATTERN "*.h"
)
install(
  FILES "${CMAKE_SOURCE_DIR}/include/curl-impersonate/webcrypto.h"
  DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/curl-impersonate"
)
# Keep static dependencies private so they do not replace system libraries.
install(
  DIRECTORY "${DEPS_INSTALL_DIR}/lib/"
  DESTINATION "${CMAKE_INSTALL_LIBDIR}/curl-impersonate"
  FILES_MATCHING
    PATTERN "*.a"
    PATTERN "*.lib"
    PATTERN "cmake" EXCLUDE
    PATTERN "pkgconfig" EXCLUDE
)
configure_file(
  "${CMAKE_SOURCE_DIR}/cmake/PrepareInstallMetadata.cmake.in"
  "${CMAKE_BINARY_DIR}/PrepareInstallMetadata.cmake"
  @ONLY
)
install(SCRIPT "${CMAKE_BINARY_DIR}/PrepareInstallMetadata.cmake")
install(
  FILES "${CMAKE_BINARY_DIR}/install-metadata/libcurl-impersonate.pc"
  DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig"
)
install(
  PROGRAMS "${CMAKE_BINARY_DIR}/install-metadata/curl-impersonate-config"
  DESTINATION ${CMAKE_INSTALL_BINDIR}
)
if(WIN32)
  file(GLOB _curl_wrapper_scripts CONFIGURE_DEPENDS "${CMAKE_SOURCE_DIR}/win/bin/curl_*.bat")
else()
  file(GLOB _curl_wrapper_scripts CONFIGURE_DEPENDS "${CMAKE_SOURCE_DIR}/bin/curl_*")
endif()
if(_curl_wrapper_scripts)
  install(PROGRAMS ${_curl_wrapper_scripts} DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

# Release workflows collect licenses separately from installation.
configure_file(
  "${CMAKE_SOURCE_DIR}/cmake/CollectLicenses.cmake.in"
  "${CMAKE_BINARY_DIR}/CollectLicenses.cmake"
  @ONLY
)

configure_file(
  "${CMAKE_SOURCE_DIR}/cmake/Uninstall.cmake.in"
  "${CMAKE_BINARY_DIR}/cmake_uninstall.cmake"
  @ONLY
)

add_custom_target(uninstall
  COMMAND ${CMAKE_COMMAND} -P "${CMAKE_BINARY_DIR}/cmake_uninstall.cmake"
  COMMENT "Uninstall files recorded in install manifests"
)
