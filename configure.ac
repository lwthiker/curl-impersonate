AC_INIT([curl-impersonate], [0.3.2], [lwt@lwthiker.com])

AC_ARG_ENABLE([static],
    [AS_HELP_STRING([--enable-static],
        [Build curl-impersonate statically with libcurl-impersonate])],
    [AC_SUBST([curl_configure_options], ["--enable-static --disable-shared"])],
    [])

AC_CONFIG_FILES([Makefile])

AC_OUTPUT
