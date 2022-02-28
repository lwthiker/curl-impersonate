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

#include <curl/curl.h>

/* Command line options. */
struct opts {
    char *outfile;
    uint16_t local_port_start;
    uint16_t local_port_end;
    char *url;
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

    memset(opts, 0, sizeof(*opts));

    while (1) {
        int option_index = 0;
        static struct option long_options[] = {
            {"local-port", required_argument, NULL, 'l'}
        };

        c = getopt_long(argc, argv, "o:", long_options, &option_index);
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
        }
    }

    if (optind < argc) {
        opts->url = argv[optind++];
    } else {
        return 1;
    }

    if (optind < argc) {
        /* Too many arguments. */
        return 1;
    }

    return 0;
}

int main(int argc, char *argv[])
{
    struct opts opts;
    CURLcode c;
    CURL *curl = NULL;
    FILE *file;

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

    c = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, fwrite);
    if (c) {
        fprintf(stderr, "curl_easy_setopt(CURLOPT_WRITEFUNCTION) failed\n");
        goto out;
    }

    c = curl_easy_setopt(curl, CURLOPT_WRITEDATA, file);
    if (c) {
        fprintf(stderr, "curl_easy_setopt(CURLOPT_WRITEDATA) failed\n");
        goto out;
    }

    if (opts.local_port_start && opts.local_port_end) {
        c = curl_easy_setopt(curl,
                             CURLOPT_LOCALPORT,
                             opts.local_port_start);
        if (c) {
            fprintf(stderr, "curl_easy_setopt(CURLOPT_LOCALPORT) failed\n");
            goto out;
        }

        c = curl_easy_setopt(curl,
                             CURLOPT_LOCALPORTRANGE,
                             opts.local_port_end - opts.local_port_start);
        if (c) {
            fprintf(stderr,
                    "curl_easy_setopt(CURLOPT_LOCALPORTRANGE) failed\n");
            goto out;
        }
    }

    c = curl_easy_setopt(curl, CURLOPT_URL, opts.url);
    if (c) {
        fprintf(stderr, "curl_easy_setopt(CURLOPT_URL) failed\n");
        goto out;
    }

    c = curl_easy_perform(curl);
    if (c) {
        fprintf(stderr, "curl_easy_perform() failed\n");
        goto out;
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
