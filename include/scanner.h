#ifndef SCANNER_H
#define SCANNER_H

#include <netdb.h>
#include <stdbool.h>
#include <stdint.h>

#define MAX_REASON_LEN 128
#define MAX_SERVICE_LEN 32

typedef enum { SCAN_PROTO_TCP, SCAN_PROTO_UDP } scan_proto_t;

typedef enum {
  SCAN_STATE_OPEN,
  SCAN_STATE_CLOSED,
  SCAN_STATE_OPEN_FILTERED,
  SCAN_STATE_ERROR
} scan_state_t;

typedef struct {
  uint16_t *values;
  size_t count;
} port_list_t;

typedef struct {
  port_list_t tcp_ports;
  port_list_t udp_ports;
  bool enable_tcp;
  bool enable_udp;
  bool output_json;
  bool resolve_dns;
  double timeout_seconds;
  int retries;
  int concurrency;
  double rate_per_second;
  char *target;
  char *display_target;
  struct addrinfo *addrs;
} scanner_options_t;

typedef struct {
  uint16_t port;
  scan_proto_t proto;
  scan_state_t state;
  char service[MAX_SERVICE_LEN];
  char reason[MAX_REASON_LEN];
} scan_result_t;

typedef struct {
  scan_result_t *items;
  size_t count;
} scan_result_set_t;

typedef struct rate_limiter rate_limiter_t;

int parse_options(int argc, char **argv, scanner_options_t *opts);
void free_options(scanner_options_t *opts);
int run_scanner(scanner_options_t *opts, scan_result_set_t *out_results);
void free_results(scan_result_set_t *results);
void emit_results(const scanner_options_t *opts,
                  const scan_result_set_t *results);

#endif
