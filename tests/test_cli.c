#define _GNU_SOURCE

#include "scanner.h"

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__GLIBC__)
#define RESET_OPTIND()                                                                 \
    do {                                                                               \
        optind = 0;                                                                    \
    } while (0)
#else
#define RESET_OPTIND()                                                                 \
    do {                                                                               \
        optind = 1;                                                                    \
    } while (0)
#endif

typedef int (*test_fn)(void);

static void reset_getopt_state(void) {
    RESET_OPTIND();
    opterr = 0;
}

static int check_defaults(void) {
    scanner_options_t opts;
    reset_getopt_state();
    char *argv[] = {"scanner", NULL};
    int rc = parse_options(1, argv, &opts);
    if (rc != 0) {
        fprintf(stderr, "parse_options default returned %d\n", rc);
        free_options(&opts);
        return 1;
    }
    if (!opts.target || strcmp(opts.target, "127.0.0.1") != 0) {
        fprintf(stderr, "default target mismatch\n");
        free_options(&opts);
        return 1;
    }
    if (!opts.enable_tcp || !opts.enable_udp) {
        fprintf(stderr, "expected both protocols enabled by default\n");
        free_options(&opts);
        return 1;
    }
    if (opts.tcp_ports.count != 25 || opts.udp_ports.count != 5) {
        fprintf(stderr, "default port counts mismatch (tcp=%zu udp=%zu)\n", opts.tcp_ports.count,
                opts.udp_ports.count);
        free_options(&opts);
        return 1;
    }
    if (opts.timeout_seconds <= 0.0 || opts.retries != 1 || opts.concurrency != 32) {
        fprintf(stderr, "default numeric options mismatch\n");
        free_options(&opts);
        return 1;
    }
    free_options(&opts);
    return 0;
}

static int check_port_parsing(void) {
    scanner_options_t opts;
    reset_getopt_state();
    char *argv[] = {"scanner", "--tcp", "1000-1002,2000", "--udp", "53,123", "localhost", NULL};
    int argc = 6;
    int rc = parse_options(argc, argv, &opts);
    if (rc != 0) {
        fprintf(stderr, "parse_options custom ports returned %d\n", rc);
        free_options(&opts);
        return 1;
    }
    if (opts.tcp_ports.count != 4) {
        fprintf(stderr, "expected 4 tcp ports, got %zu\n", opts.tcp_ports.count);
        free_options(&opts);
        return 1;
    }
    if (opts.tcp_ports.values[0] != 1000 || opts.tcp_ports.values[1] != 1001 ||
        opts.tcp_ports.values[2] != 1002 || opts.tcp_ports.values[3] != 2000) {
        fprintf(stderr, "tcp port sequence incorrect\n");
        free_options(&opts);
        return 1;
    }
    if (opts.udp_ports.count != 2 || opts.udp_ports.values[0] != 53 || opts.udp_ports.values[1] != 123) {
        fprintf(stderr, "udp port sequence incorrect\n");
        free_options(&opts);
        return 1;
    }
    if (!opts.resolve_dns || !opts.display_target) {
        fprintf(stderr, "expected DNS resolution and display target\n");
        free_options(&opts);
        return 1;
    }
    free_options(&opts);
    return 0;
}

static int check_help_flag(void) {
    scanner_options_t opts;
    reset_getopt_state();
    char *argv[] = {"scanner", "--help", NULL};
    int rc = parse_options(2, argv, &opts);
    if (rc != 1) {
        fprintf(stderr, "--help should return 1, got %d\n", rc);
        free_options(&opts);
        return 1;
    }
    free_options(&opts);
    return 0;
}

static int check_invalid_tcp_list(void) {
    scanner_options_t opts;
    reset_getopt_state();
    char *argv[] = {"scanner", "--tcp", "bad", "127.0.0.1", NULL};
    int rc = parse_options(4, argv, &opts);
    if (rc == 0) {
        fprintf(stderr, "invalid TCP list should fail\n");
        free_options(&opts);
        return 1;
    }
    free_options(&opts);
    return 0;
}

static const struct {
    const char *name;
    test_fn fn;
} TESTS[] = {
    {"defaults", check_defaults},
    {"port parsing", check_port_parsing},
    {"help flag", check_help_flag},
    {"invalid tcp list", check_invalid_tcp_list},
};

int main(void) {
    size_t total = sizeof(TESTS) / sizeof(TESTS[0]);
    size_t failures = 0;
    for (size_t i = 0; i < total; ++i) {
        if (TESTS[i].fn() != 0) {
            fprintf(stderr, "[FAIL] %s\n", TESTS[i].name);
            ++failures;
        } else {
            printf("[PASS] %s\n", TESTS[i].name);
        }
    }
    if (failures != 0) {
        fprintf(stderr, "%zu/%zu tests failed\n", failures, total);
        return EXIT_FAILURE;
    }
    printf("All %zu tests passed\n", total);
    return EXIT_SUCCESS;
}

