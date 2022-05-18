/*
 * A simple program that uses libcurl to fetch a URL and output to stdout.
 *
 * It is intended to be linked against the "regular" libcurl, with
 * "libcurl-impersonate" loaded via LD_PRELOAD. It does the bare minimum
 * to support the Python tests.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <stdbool.h>

#include <curl/curl.h>

/* Support up to 16 URLs */
#define MAX_URLS 16
/* Command line options. */
struct opts {
    char *outfile;
    uint16_t local_port_start;
    uint16_t local_port_end;
    bool insecure;
    char *urls[MAX_URLS];
};

int parse_ports_range(char *str, uint16_t *start, uint16_t *end)
{
    char port[32];
    char *sep;
    unsigned long int tmp;

    if (strlen(str) >= sizeof(port)) {
        return 1;
    }
    strncpy(port, str, sizeof(port) - 1);
    sep = strchr(port, '-');
    if (!sep) {
        return 1;
    }
    *sep = 0;

    errno = 0;
    tmp = strtoul(port, NULL, 10);
    if (errno || tmp == 0 || tmp > 0xffff) {
        return 1;
    }
    *start = (uint16_t)tmp;
    tmp = strtoul(sep + 1, NULL, 10);
    if (errno || tmp == 0 || tmp > 0xffff || tmp < *start) {
        return 1;
    }
    *end = (uint16_t)tmp;

    return 0;
}

int parse_opts(int argc, char **argv, struct opts *opts)
{
    int c;
    int r;
    int i;

    memset(opts, 0, sizeof(*opts));

    opts->insecure = false;

    while (1) {
        int option_index = 0;
        static struct option long_options[] = {
            {"local-port", required_argument, NULL, 'l'}
        };

        c = getopt_long(argc, argv, "o:k", long_options, &option_index);
        if (c == -1) {
            break;
        }

        switch (c) {
        case 'l':
            r = parse_ports_range(optarg,
                                  &opts->local_port_start,
                                  &opts->local_port_end);
            if (r) {
                return r;
            }
            break;
        case 'o':
            opts->outfile = optarg;
            break;
        case 'k':
            opts->insecure = true;
            break;
        }
    }

    /* No URL supplied. */
    if (optind >= argc) {
        return 1;
    }

    /* The rest of the options are URLs */
    i = 0;
    while (optind < argc) {
        opts->urls[i++] = argv[optind++];
    }

    return 0;
}

/* Set all options except for the URL. */
int set_opts(CURL *curl, struct opts *opts, FILE *file)
{
    CURLcode c;

    c = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, fwrite);
    if (c) {
        fprintf(stderr, "curl_easy_setopt(CURLOPT_WRITEFUNCTION) failed\n");
        return 1;
    }

    c = curl_easy_setopt(curl, CURLOPT_WRITEDATA, file);
    if (c) {
        fprintf(stderr, "curl_easy_setopt(CURLOPT_WRITEDATA) failed\n");
        return 1;
    }

    if (opts->local_port_start && opts->local_port_end) {
        c = curl_easy_setopt(curl,
                             CURLOPT_LOCALPORT,
                             opts->local_port_start);
        if (c) {
            fprintf(stderr, "curl_easy_setopt(CURLOPT_LOCALPORT) failed\n");
            return 1;
        }

        c = curl_easy_setopt(curl,
                             CURLOPT_LOCALPORTRANGE,
                             opts->local_port_end - opts->local_port_start);
        if (c) {
            fprintf(stderr,
                    "curl_easy_setopt(CURLOPT_LOCALPORTRANGE) failed\n");
            return 1;
        }
    }

    if (opts->insecure) {
        c = curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
        if (c) {
            fprintf(stderr, "curl_easy_setopt(CURLOPT_SSL_VERIFYPEER) failed\n");
            return 1;
        }
        c = curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0);
        if (c) {
            fprintf(stderr, "curl_easy_setopt(CURLOPT_SSL_VERIFYHOST) failed\n");
            return 1;
        }
    }

    return 0;
}

int main(int argc, char *argv[])
{
    struct opts opts;
    CURLcode c;
    CURL *curl = NULL;
    FILE *file;
    int i;

    if (parse_opts(argc, argv, &opts)) {
        fprintf(stderr, "Invalid arguments\n");
        exit(1);
    }

    if (opts.outfile) {
        file = fopen(opts.outfile, "w");
        if (!file) {
            fprintf(stderr, "Failed opening %s for writing\n", opts.outfile);
            exit(1);
        }
    } else {
        file = stdout;
    }

    c = curl_global_init(CURL_GLOBAL_DEFAULT);
    if (c) {
        fprintf(stderr, "curl_global_init() failed\n");
        goto out_close;
    }

    curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "curl_easy_init() failed\n");
        c = 1;
        goto out;
    }

    for (i = 0; i <= MAX_URLS && opts.urls[i]; i++) {
        if (set_opts(curl, &opts, file)) {
            goto out;
        }

        c = curl_easy_setopt(curl, CURLOPT_URL, opts.urls[i]);
        if (c) {
            fprintf(stderr, "curl_easy_setopt(CURLOPT_URL) failed\n");
            goto out;
        }

        c = curl_easy_perform(curl);
        if (c) {
            fprintf(stderr, "curl_easy_perform() failed\n");
            goto out;
        }

        /* Re-use the curl handle. */
        curl_easy_reset(curl);
    }

    c = 0;

out:
    if (curl) {
        curl_easy_cleanup(curl);
    }
    curl_global_cleanup();
out_close:
    if (file) {
        fclose(file);
    }
    return c;
}
