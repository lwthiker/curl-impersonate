AC_INIT([curl-impersonate], [0.3.2], [lwt@lwthiker.com])

AC_ARG_ENABLE([static],
    [AS_HELP_STRING([--enable-static],
        [Build curl-impersonate statically with libcurl-impersonate])],
    [AC_SUBST([curl_configure_options], ["--enable-static --disable-shared"])],
    [])

# BoringSSL requires cmake 3.5+, which is sometimes available under
# "cmake3" instead of "cmake"
AC_CHECK_PROGS([cmake], [cmake3 cmake])

AC_CHECK_PROGS([ninja], [ninja ninja-build])

AC_CONFIG_FILES([Makefile])

AC_OUTPUT
