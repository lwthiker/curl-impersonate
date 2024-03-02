AC_INIT([curl-impersonate], [0.6.1], [lwt@lwthiker.com])

AC_CANONICAL_BUILD
AC_CANONICAL_HOST

AC_PROG_CC
AC_PROG_CXX

AC_CHECK_TOOL([STRIP], [strip])

AC_ARG_ENABLE([static],
    [AS_HELP_STRING([--enable-static],
        [Build curl-impersonate statically with libcurl-impersonate])],
    [AC_SUBST([static_build], ["$enableval"])],
    [AC_SUBST([static_build], ["no"])])

# Let the user optionally specify the path to zlib.
# This is useful when cross compiling.
# The Makefile will pass on the path to curl's own configure script.
AC_ARG_WITH([zlib],
    [AS_HELP_STRING([--with-zlib=PATH],
        [Search for zlib in PATH. Useful when cross compiling])],
    [with_zlib="$withval"],
    [with_zlib="check"])

AS_IF(
    # User provided --without-zlib, which we don't support
    [test x"$with_zlib" = xno],
    [AC_MSG_ERROR(building without zlib is not supported)],
    # User didn't provide --with-zlib at all, or provided --with-zlib without
    # a path. Check if zlib can be linked against using the default linker flags.
    [test x"$with_zlib" = xcheck -o x"$with_zlib" = xyes],
        [AC_CHECK_LIB([z], [inflateEnd],
            [AC_SUBST([with_zlib], [""])],
            [AC_MSG_ERROR(failed to find zlib)])],
    # User provided --with-zlib with a path.
    [AC_SUBST([with_zlib], ["$with_zlib"])])

# Path to CA certificates.
# These options will be passed as-is to curl's configure script.
# Useful when cross compiling, since curl's configure script doesn't know
# where to look for these files in that case.
AC_ARG_WITH([ca-bundle],
    [AS_HELP_STRING([--with-ca-bundle=FILE],
        [Path to be passed to curl's --with-ca-bundle configure option. \
         Useful when cross compiling. \
         Relevant only for the Chrome build.])],
    [AC_SUBST([with_ca_bundle], ["$withval"])],
    [AC_SUBST([with_ca_bundle], [""])])
AC_ARG_WITH([ca-path],
    [AS_HELP_STRING([--with-ca-path=DIRECTORY],
        [Path to be passed to curl's --with-ca-path configure option. \
         Useful when cross compiling. \
         Relevant only for the chrome build.])],
    [AC_SUBST([with_ca_path], ["$withval"])],
    [AC_SUBST([with_ca_path], [""])])

# Path to a directory containing libnssckbi.so, the file that contains the root
# certificates needed for nss.
# Useful when cross compiling. When building natively, curl's patched configure
# script will attempt to locate it on the local system instead.
AC_ARG_WITH([libnssckbi],
    [AS_HELP_STRING([--with-libnssckbi=DIRECTORY],
        [Path to a directory containing libnssckbi.so. \
         Useful when cross compiling. \
         Relevant only for the Firefox build.])],
    [AC_SUBST([with_libnssckbi], ["$withval"])],
    [AC_SUBST([with_libnssckbi], [""])])

AC_ARG_VAR([CURL_CONFIG_FLAGS], ["configuration flags to be passed down to curls 'configure'"])

# BoringSSL requires cmake 3.5+, which is sometimes available under
# "cmake3" instead of "cmake"
AC_CHECK_PROGS([cmake], [cmake3 cmake])

AC_CHECK_PROGS([ninja], [ninja ninja-build])

AC_CONFIG_FILES([Makefile])

AC_OUTPUT
