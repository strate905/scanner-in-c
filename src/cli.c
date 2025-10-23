/*
 * cli.c - Command-line Interface Module
 *
 * Copyright (C) 2025 Strategos Network Scanner Project
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * This module handles argument parsing, validation, and DNS resolution for the
 * port scanner. It demonstrates:
 * - Using getopt_long() for robust command-line parsing
 * - Safe string-to-number conversion with strtol() and strtod()
 * - Dynamic memory allocation with realloc() for variable-sized lists
 * - DNS resolution with getaddrinfo() supporting both IPv4 and IPv6
 */

#define _GNU_SOURCE  // Required for getopt_long() and getnameinfo()
#include "scanner.h"

#include <errno.h>
#include <getopt.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Helper structure for passing default port sets.
 * Uses const pointers to avoid unnecessary copies of static data.
 */
typedef struct {
  const uint16_t *values;
  size_t count;
} default_ports_t;

/*
 * Default port sets based on common services.
 * TCP: 25 most common ports (web, SSH, mail, databases, RDP, etc.)
 * UDP: 5 most common ports (DNS, NTP, SNMP, IKE, SSDP)
 */
static const uint16_t DEFAULT_TCP_PORTS[] = {
    80,   443,  22,   21,  25,  23,  53,  110, 135,  139,  143,  445, 3389,
    3306, 8080, 5900, 993, 995, 465, 587, 111, 2049, 1025, 1723, 554};
static const uint16_t DEFAULT_UDP_PORTS[] = {53, 123, 161, 500, 1900};

/*
 * Frees memory allocated for a port list and resets the structure.
 *
 * Best Practice: Always set pointers to NULL after freeing to avoid
 * use-after-free bugs. This makes the structure safe to free multiple times
 * (idempotent operation).
 */
static void free_port_list(port_list_t *list) {
  if (list->values) {
    free(list->values);
  }
  list->values = NULL;
  list->count = 0;
}

/*
 * Parses a single port token, supporting both individual ports and ranges.
 *
 * Accepted formats:
 *   "80"          -> single port (begin=80, end=80)
 *   "8000-8100"   -> inclusive range (begin=8000, end=8100)
 *
 * Educational Notes:
 * - strtol() is preferred over atoi() because it provides error detection
 * - We must clear errno before calling strtol() to detect overflow (ERANGE)
 * - endptr tells us where parsing stopped, helping detect invalid characters
 * - Port numbers are 16-bit (0-65535), but 0 is reserved, so valid range is 1-65535
 * - We reject reversed ranges (e.g., "8100-8000") as logically invalid
 *
 * Returns: 0 on success, -1 on invalid input
 */
static int parse_port_range(const char *token, uint16_t *out_begin,
                            uint16_t *out_end) {
  char *endptr = NULL;
  errno = 0;  // Must clear errno before strtol() to detect errors reliably
  long begin = strtol(token, &endptr, 10);

  // Validate: check for conversion errors and valid port range
  if (errno != 0 || begin < 1 || begin > 65535) {
    return -1;
  }

  // Case 1: Single port (no hyphen found, parsing consumed entire string)
  if (*endptr == '\0') {
    *out_begin = (uint16_t)begin;
    *out_end = (uint16_t)begin;
    return 0;
  }

  // Case 2: Range syntax - must have hyphen followed by more digits
  if (*endptr != '-' || *(endptr + 1) == '\0') {
    return -1;  // Invalid: either not a hyphen or hyphen at end
  }

  // Parse the end of the range
  const char *end_token = endptr + 1;
  errno = 0;
  long end = strtol(end_token, &endptr, 10);

  // Validate: check for errors, valid range, consumed entire string, and logical order
  if (errno != 0 || end < 1 || end > 65535 || *endptr != '\0' || end < begin) {
    return -1;
  }

  *out_begin = (uint16_t)begin;
  *out_end = (uint16_t)end;
  return 0;
}

/*
 * Parses a comma-separated port list with support for ranges.
 *
 * Input examples:
 *   "22,80,443"           -> three ports
 *   "22, 80-82, 443"      -> five ports (whitespace tolerated)
 *   "8000-8100"           -> 101 ports
 *
 * Educational Notes on Dynamic Memory Management:
 * - We start with capacity=16 and double it when full (amortized O(1) append)
 * - realloc() preserves existing data while growing the buffer
 * - CRITICAL: realloc() can fail and return NULL, so we must check before
 *   overwriting the original pointer (using 'tmp' variable)
 * - If realloc() fails after multiple successful growths, we must free the
 *   original allocation to avoid memory leaks
 *
 * Thread Safety:
 * - strtok_r() is the reentrant version of strtok(), safe for multithreaded code
 * - The 'saveptr' maintains parsing state between calls
 *
 * Returns: 0 on success (with allocated port array), -1 on error
 */
static int parse_port_list(const char *text, port_list_t *out_list) {
  free_port_list(out_list);
  if (!text || *text == '\0') {
    return -1;
  }

  // Start with reasonable initial capacity to avoid excessive reallocations
  size_t capacity = 16;
  uint16_t *ports = calloc(capacity, sizeof(uint16_t));
  if (!ports) {
    return -1;
  }
  size_t count = 0;

  // strdup() creates a copy because strtok_r() modifies the string in-place
  char *copy = strdup(text);
  if (!copy) {
    free(ports);
    return -1;
  }

  char *token = NULL;
  char *saveptr = NULL;  // State variable for strtok_r()

  // Split on commas, processing each token as a port or range
  for (token = strtok_r(copy, ",", &saveptr); token;
       token = strtok_r(NULL, ",", &saveptr)) {

    // Skip leading whitespace (tolerates input like "22, 80, 443")
    while (*token == ' ') {
      ++token;
    }
    if (*token == '\0') {
      continue;  // Empty token (e.g., from trailing comma)
    }

    uint16_t begin = 0;
    uint16_t end = 0;
    if (parse_port_range(token, &begin, &end) != 0) {
      free(ports);
      free(copy);
      return -1;
    }

    // Expand range into individual ports (inclusive on both ends)
    for (uint16_t port = begin; port <= end; ++port) {
      // Dynamic array growth: double capacity when full
      if (count == capacity) {
        capacity *= 2;
        // IMPORTANT: Use temporary pointer to safely handle realloc() failure
        uint16_t *tmp = realloc(ports, capacity * sizeof(uint16_t));
        if (!tmp) {
          // realloc() failed - must free original allocation
          free(ports);
          free(copy);
          return -1;
        }
        ports = tmp;  // Safe to update pointer only after success
      }
      ports[count++] = port;
    }
  }

  free(copy);

  // Reject empty lists (all tokens were invalid)
  if (count == 0) {
    free(ports);
    return -1;
  }

  out_list->values = ports;
  out_list->count = count;
  return 0;
}

static int set_default_ports(const default_ports_t *defaults,
                             port_list_t *out_list) {
  free_port_list(out_list);
  out_list->values = calloc(defaults->count, sizeof(uint16_t));
  if (!out_list->values) {
    return -1;
  }
  memcpy(out_list->values, defaults->values,
         defaults->count * sizeof(uint16_t));
  out_list->count = defaults->count;
  return 0;
}

static void print_usage(FILE *stream, const char *prog) {
  fprintf(stream,
          "Usage: %s [options] <target>\n"
          "\n"
          "Options:\n"
          "  --tcp PORTS         Comma/range list of TCP ports (default "
          "top-common set)\n"
          "  --udp PORTS         Comma/range list of UDP ports (default "
          "top-common set)\n"
          "  --timeout SECONDS   Socket timeout (default 1.0)\n"
          "  --retries N         Retries per port (default 1)\n"
          "  --concurrency N     Parallel workers (default 32)\n"
          "  --rate PPS          Max probes per second (default unlimited)\n"
          "  --json              Emit JSON instead of Markdown\n"
          "  --no-dns            Skip DNS resolution (target must be numeric)\n"
          "  -h, --help          Show this help message\n",
          prog);
}

/*
 * Resolves the target hostname/IP to a linked list of socket addresses.
 *
 * Educational Notes on Modern DNS Resolution:
 * - getaddrinfo() is the modern replacement for gethostbyname()
 * - It supports both IPv4 and IPv6 transparently (AF_UNSPEC)
 * - It returns a linked list of addresses (host may have multiple IPs)
 * - AI_NUMERICHOST flag disables DNS lookups (requires numeric IP)
 *
 * Why getnameinfo() for display?
 * - Even when user provides a hostname, we convert it back to numeric form
 * - This cached display value avoids DNS latency when printing results
 * - NI_NUMERICHOST flag ensures we get IP address, not reverse DNS lookup
 *
 * Memory Management:
 * - getaddrinfo() allocates memory that must be freed with freeaddrinfo()
 * - We store the result in opts->addrs for later use by scanner threads
 * - This is freed in free_options() after scanning completes
 *
 * Returns: 0 on success, -1 on resolution failure
 */
static int resolve_target(scanner_options_t *opts) {
  struct addrinfo hints = {
      .ai_family = AF_UNSPEC,    // Accept both IPv4 and IPv6
      .ai_socktype = 0,          // Any socket type (we'll specify per-scan)
      .ai_protocol = 0,          // Any protocol
  };

  if (!opts->resolve_dns) {
    // AI_NUMERICHOST: Target must be numeric IP, no DNS lookup
    hints.ai_flags |= AI_NUMERICHOST;
  }

  struct addrinfo *res = NULL;
  int rc = getaddrinfo(opts->target, NULL, &hints, &res);
  if (rc != 0) {
    // gai_strerror() converts getaddrinfo error codes to strings
    fprintf(stderr, "Failed to resolve target '%s': %s\n", opts->target,
            gai_strerror(rc));
    return -1;
  }

  opts->addrs = res;  // Store linked list of addresses

  // Convert first resolved address back to numeric form for display
  if (opts->display_target == NULL) {
    struct addrinfo *addr = res;
    for (; addr; addr = addr->ai_next) {
      char host[NI_MAXHOST];  // Buffer for numeric IP string
      // getnameinfo(): reverse of getaddrinfo(), converts sockaddr to string
      int err = getnameinfo(addr->ai_addr, addr->ai_addrlen, host, sizeof(host),
                            NULL, 0, NI_NUMERICHOST);
      if (err == 0) {
        // Cache numeric IP so we don't need DNS during output phase
        opts->display_target = strdup(host);
        break;
      }
    }
  }
  return 0;
}

static void ensure_display_target(scanner_options_t *opts, const char *input) {
  if (opts->display_target) {
    return;
  }
  opts->display_target = strdup(input);
}

int parse_options(int argc, char **argv, scanner_options_t *opts) {
  memset(opts, 0, sizeof(*opts));
  opts->enable_tcp = true;
  opts->enable_udp = true;
  opts->resolve_dns = true;
  opts->timeout_seconds = 1.0;
  opts->retries = 1;
  opts->concurrency = 32;
  opts->rate_per_second = 0.0;

  static struct option long_opts[] = {
      {"tcp", required_argument, NULL, 1},
      {"udp", required_argument, NULL, 2},
      {"timeout", required_argument, NULL, 3},
      {"retries", required_argument, NULL, 4},
      {"concurrency", required_argument, NULL, 5},
      {"rate", required_argument, NULL, 6},
      {"json", no_argument, NULL, 7},
      {"no-dns", no_argument, NULL, 8},
      {"help", no_argument, NULL, 'h'},
      {0, 0, 0, 0},
  };

  int opt;
  int long_index = 0;
  while ((opt = getopt_long(argc, argv, "h", long_opts, &long_index)) != -1) {
    switch (opt) {
    case 1:
      if (parse_port_list(optarg, &opts->tcp_ports) != 0) {
        fprintf(stderr, "Invalid TCP port list: %s\n", optarg);
        return -1;
      }
      opts->enable_tcp = true;
      break;
    case 2:
      if (parse_port_list(optarg, &opts->udp_ports) != 0) {
        fprintf(stderr, "Invalid UDP port list: %s\n", optarg);
        return -1;
      }
      opts->enable_udp = true;
      break;
    case 3: {
      errno = 0;
      char *endptr = NULL;
      double val = strtod(optarg, &endptr);
      if (errno != 0 || endptr == optarg || val <= 0.0) {
        fprintf(stderr, "Invalid timeout value: %s\n", optarg);
        return -1;
      }
      opts->timeout_seconds = val;
      break;
    }
    case 4: {
      errno = 0;
      char *endptr = NULL;
      long val = strtol(optarg, &endptr, 10);
      if (errno != 0 || endptr == optarg || val < 1 || val > 10) {
        fprintf(stderr, "Invalid retries value: %s\n", optarg);
        return -1;
      }
      opts->retries = (int)val;
      break;
    }
    case 5: {
      errno = 0;
      char *endptr = NULL;
      long val = strtol(optarg, &endptr, 10);
      if (errno != 0 || endptr == optarg || val < 1 || val > 1024) {
        fprintf(stderr, "Invalid concurrency value: %s\n", optarg);
        return -1;
      }
      opts->concurrency = (int)val;
      break;
    }
    case 6: {
      errno = 0;
      char *endptr = NULL;
      double val = strtod(optarg, &endptr);
      if (errno != 0 || endptr == optarg || val < 0.0) {
        fprintf(stderr, "Invalid rate limit: %s\n", optarg);
        return -1;
      }
      opts->rate_per_second = val;
      break;
    }
    case 7:
      opts->output_json = true;
      break;
    case 8:
      opts->resolve_dns = false;
      break;
    case 'h':
    default:
      print_usage(opt == 'h' ? stdout : stderr, argv[0]);
      return opt == 'h' ? 1 : -1;
    }
  }

  const int remaining = argc - optind;
  if (remaining > 1) {
    fprintf(stderr, "Too many positional arguments.\n");
    print_usage(stderr, argv[0]);
    return -1;
  }
  const char *input_target = remaining == 1 ? argv[optind] : "127.0.0.1";
  opts->target = strdup(input_target);
  if (!opts->target) {
    fprintf(stderr, "Out of memory.\n");
    return -1;
  }
  ensure_display_target(opts, input_target);

  if (!opts->enable_tcp && !opts->enable_udp) {
    fprintf(stderr, "At least one of --tcp or --udp must be enabled.\n");
    return -1;
  }

  if (opts->enable_tcp && opts->tcp_ports.count == 0) {
    if (set_default_ports(&(default_ports_t){DEFAULT_TCP_PORTS,
                                             sizeof(DEFAULT_TCP_PORTS) /
                                                 sizeof(DEFAULT_TCP_PORTS[0])},
                          &opts->tcp_ports) != 0) {
      fprintf(stderr, "Failed to set default TCP ports.\n");
      return -1;
    }
  }
  if (opts->enable_udp && opts->udp_ports.count == 0) {
    if (set_default_ports(&(default_ports_t){DEFAULT_UDP_PORTS,
                                             sizeof(DEFAULT_UDP_PORTS) /
                                                 sizeof(DEFAULT_UDP_PORTS[0])},
                          &opts->udp_ports) != 0) {
      fprintf(stderr, "Failed to set default UDP ports.\n");
      return -1;
    }
  }

  if (resolve_target(opts) != 0) {
    return -1;
  }
  return 0;
}

void free_options(scanner_options_t *opts) {
  free_port_list(&opts->tcp_ports);
  free_port_list(&opts->udp_ports);
  if (opts->target) {
    free(opts->target);
    opts->target = NULL;
  }
  if (opts->display_target) {
    free(opts->display_target);
    opts->display_target = NULL;
  }
  if (opts->addrs) {
    freeaddrinfo(opts->addrs);
    opts->addrs = NULL;
  }
}
