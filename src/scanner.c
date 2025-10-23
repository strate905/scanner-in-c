/*
 * scanner.c - Core Scanning Engine
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
 * This module implements the multi-threaded port scanning engine. It demonstrates:
 * - pthread-based concurrency with worker thread pools
 * - Non-blocking sockets with poll() for timeout control
 * - TCP connect() scanning (unprivileged technique)
 * - UDP scanning with ICMP error detection
 * - Thread-safe task queue with mutex protection
 * - Rate limiting using CLOCK_MONOTONIC and nanosleep()
 * - Lock-free result storage via pre-allocated indexed arrays
 *
 * Architecture:
 * 1. Main thread builds task queue and spawns worker threads
 * 2. Workers atomically dequeue tasks, perform scans, write to pre-allocated results
 * 3. Rate limiter enforces global probes-per-second limit across all workers
 * 4. Main thread joins workers and returns consolidated results
 */

#define _GNU_SOURCE  // Required for CLOCK_MONOTONIC
#include "scanner.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/*
 * Represents a single port scanning task.
 * result_index points to pre-allocated slot in results array (lock-free writes).
 */
typedef struct {
  scan_proto_t proto;
  uint16_t port;
  size_t result_index;  // Pre-allocated result slot (avoids locks during scan)
} scan_task_t;

/*
 * Thread-safe task queue using mutex for atomic dequeuing.
 * Workers increment 'next' atomically to claim tasks.
 */
typedef struct {
  scan_task_t *tasks;
  size_t count;
  size_t next;            // Next task index (protected by mutex)
  pthread_mutex_t mutex;  // Protects 'next' field only
} task_queue_t;

/*
 * Rate limiter enforces global probes-per-second limit.
 * Uses CLOCK_MONOTONIC (unaffected by system time changes) for accurate timing.
 */
struct rate_limiter {
  double interval;              // Minimum seconds between probes
  pthread_mutex_t mutex;        // Protects timing state
  struct timespec last_fire;    // Last probe timestamp
  int initialized;              // First probe doesn't wait
};

/*
 * Context shared among all worker threads (read-only, no locks needed).
 * Each worker atomically dequeues tasks and writes to indexed result slots.
 */
typedef struct {
  const scanner_options_t *opts;
  const struct addrinfo *addrs;
  task_queue_t *queue;
  scan_result_set_t *results;
  rate_limiter_t *limiter;
} worker_ctx_t;

static int task_queue_init(task_queue_t *queue, size_t count) {
  queue->tasks = calloc(count, sizeof(scan_task_t));
  if (!queue->tasks) {
    return -1;
  }
  queue->count = count;
  queue->next = 0;
  if (pthread_mutex_init(&queue->mutex, NULL) != 0) {
    free(queue->tasks);
    return -1;
  }
  return 0;
}

static void task_queue_destroy(task_queue_t *queue) {
  pthread_mutex_destroy(&queue->mutex);
  free(queue->tasks);
  queue->tasks = NULL;
  queue->count = 0;
  queue->next = 0;
}

static int rate_limiter_init(rate_limiter_t *limiter, double rate_per_second) {
  // Precompute the minimum probe spacing once so worker threads only consult
  // shared state.
  limiter->interval = (rate_per_second > 0.0) ? (1.0 / rate_per_second) : 0.0;
  limiter->initialized = 0;
  if (pthread_mutex_init(&limiter->mutex, NULL) != 0) {
    return -1;
  }
  limiter->last_fire.tv_sec = 0;
  limiter->last_fire.tv_nsec = 0;
  return 0;
}

static void rate_limiter_destroy(rate_limiter_t *limiter) {
  pthread_mutex_destroy(&limiter->mutex);
}

/*
 * Enforces rate limiting by sleeping if necessary.
 *
 * Educational Notes on High-Precision Timing:
 * - CLOCK_MONOTONIC: Monotonically increasing clock, unaffected by system time
 *   adjustments (NTP, daylight saving, admin changes). Essential for intervals.
 * - struct timespec: Provides nanosecond precision (tv_sec + tv_nsec)
 * - nanosleep(): Sleep with nanosecond precision (better than sleep()/usleep())
 *
 * Rate Limiting Algorithm (Token Bucket):
 * 1. Calculate elapsed time since last probe
 * 2. If elapsed < interval, sleep for (interval - elapsed)
 * 3. Update last_fire timestamp to current time
 * 4. First probe initializes timestamp without waiting
 *
 * Thread Safety:
 * - Mutex protects last_fire timestamp and initialized flag
 * - All workers synchronize through this shared limiter
 * - This creates a global rate limit across all threads
 */
static void rate_limiter_wait(rate_limiter_t *limiter) {
  if (!limiter || limiter->interval <= 0.0) {
    return;  // Rate limiting disabled
  }

  pthread_mutex_lock(&limiter->mutex);

  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);

  // First probe: initialize timestamp without waiting
  if (!limiter->initialized) {
    limiter->last_fire = now;
    limiter->initialized = 1;
    pthread_mutex_unlock(&limiter->mutex);
    return;
  }

  // Calculate elapsed time since last probe (in seconds with decimal precision)
  double elapsed = (double)(now.tv_sec - limiter->last_fire.tv_sec) +
                   (double)(now.tv_nsec - limiter->last_fire.tv_nsec) / 1e9;

  // If not enough time has passed, sleep for the remaining interval
  if (elapsed < limiter->interval) {
    double remaining = limiter->interval - elapsed;

    // Convert floating-point seconds to timespec (seconds + nanoseconds)
    struct timespec req = {
        .tv_sec = (time_t)remaining,  // Integer seconds
        .tv_nsec = (long)((remaining - (double)(time_t)remaining) * 1e9),  // Fractional part
    };

    // nanosleep() can be interrupted by signals, but we ignore that here
    nanosleep(&req, NULL);

    // Refresh timestamp after sleeping
    clock_gettime(CLOCK_MONOTONIC, &now);
  }

  // Update last_fire for next probe
  limiter->last_fire = now;
  pthread_mutex_unlock(&limiter->mutex);
}

static const char *guess_service(scan_proto_t proto, uint16_t port) {
  static const struct {
    uint16_t port;
    const char *name;
  } common_map[] = {
      {21, "ftp"},          {22, "ssh"},    {23, "telnet"},
      {25, "smtp"},         {53, "dns"},    {80, "http"},
      {110, "pop3"},        {123, "ntp"},   {135, "epmap"},
      {139, "netbios-ssn"}, {143, "imap"},  {161, "snmp"},
      {443, "https"},       {465, "smtps"}, {500, "isakmp"},
      {587, "submission"},  {993, "imaps"}, {995, "pop3s"},
      {1025, "rpc"},        {1900, "ssdp"}, {2049, "nfs"},
      {3306, "mysql"},      {3389, "rdp"},  {5900, "vnc"},
      {8080, "http-alt"},
  };
  size_t count = sizeof(common_map) / sizeof(common_map[0]);
  for (size_t i = 0; i < count; ++i) {
    if (common_map[i].port == port) {
      return common_map[i].name;
    }
  }
  (void)proto;
  return "";
}

/*
 * Sets a socket to non-blocking mode.
 *
 * Educational Notes on Non-Blocking I/O:
 * - By default, sockets are blocking: operations wait until complete
 * - Non-blocking mode: operations return immediately with EAGAIN/EWOULDBLOCK
 * - Essential for implementing timeouts with poll()/select()
 * - fcntl() with F_GETFL/F_SETFL modifies file descriptor flags
 *
 * Why Non-Blocking for TCP Connect Scanning?
 * - Blocking connect() waits for full TCP handshake or OS timeout (often 75s)
 * - Non-blocking connect() returns immediately with EINPROGRESS
 * - We then use poll() to wait with our custom timeout (e.g., 1 second)
 * - This gives us precise control over connection attempt duration
 */
static int set_nonblocking(int fd) {
  int flags = fcntl(fd, F_GETFL, 0);  // Get current flags
  if (flags < 0) {
    return -1;
  }
  // Set O_NONBLOCK flag while preserving other flags
  if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
    return -1;
  }
  return 0;
}

/*
 * Assigns port number to a sockaddr structure (IPv4 or IPv6).
 *
 * Educational Notes on Socket Address Structures:
 * - sockaddr is a generic structure; actual layout depends on sa_family
 * - AF_INET uses sockaddr_in (IPv4: 4-byte address + 2-byte port)
 * - AF_INET6 uses sockaddr_in6 (IPv6: 16-byte address + 2-byte port)
 * - Port must be in network byte order (big-endian) using htons()
 *
 * Why htons()?
 * - Host byte order varies by architecture (little-endian on x86, big-endian on some)
 * - Network byte order is standardized as big-endian (MSB first)
 * - htons() = "host to network short" converts 16-bit values
 * - Similarly: htonl() for 32-bit, ntohs() and ntohl() for reverse conversion
 *
 * Safety: We check size to ensure the cast is valid before dereferencing.
 */
static void assign_port(struct sockaddr *addr, socklen_t len, uint16_t port) {
  if (addr->sa_family == AF_INET && len >= sizeof(struct sockaddr_in)) {
    // IPv4: Cast to sockaddr_in and set port field
    struct sockaddr_in *in = (struct sockaddr_in *)addr;
    in->sin_port = htons(port);  // Convert to network byte order
  } else if (addr->sa_family == AF_INET6 &&
             len >= sizeof(struct sockaddr_in6)) {
    // IPv6: Cast to sockaddr_in6 and set port field
    struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)addr;
    in6->sin6_port = htons(port);
  }
}

/*
 * Performs a TCP connect scan on a single port.
 *
 * TCP Connect Scan (Unprivileged Technique):
 * - Uses standard connect() system call (no raw sockets required)
 * - Completes full TCP three-way handshake:
 *   1. Client sends SYN
 *   2. Server responds with SYN-ACK (port open) or RST (port closed)
 *   3. Client sends ACK to complete handshake
 * - OS logs show the connection, making it easy to detect
 *
 * State Determination:
 * - OPEN: connect() succeeds (SYN-ACK received, handshake completed)
 * - CLOSED: ECONNREFUSED errno (RST packet received from host)
 * - OPEN|FILTERED: Timeout (packets dropped by firewall, or host down)
 * - ERROR: Socket creation failure or unexpected errors
 *
 * Non-Blocking Connect Flow:
 * 1. Create socket in non-blocking mode
 * 2. Call connect() - returns immediately with EINPROGRESS
 * 3. Use poll() with POLLOUT to wait for socket to become writable
 * 4. Check SO_ERROR sockopt to determine actual connection result
 *
 * Educational Notes:
 * - poll() is more modern than select() (no FD_SETSIZE limit)
 * - POLLOUT: socket is writable (connect completed, success or failure)
 * - SO_ERROR: retrieves pending error without clearing errno
 * - We iterate through all resolved addresses (IPv4 and IPv6)
 */
static scan_state_t tcp_attempt(const struct addrinfo *addrs, uint16_t port,
                                double timeout, char *reason,
                                size_t reason_len) {
  const struct addrinfo *addr = NULL;
  int last_err = 0;

  // Try each resolved address (host may have multiple IPs)
  for (addr = addrs; addr; addr = addr->ai_next) {
    int fd = socket(addr->ai_family, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) {
      last_err = errno;
      continue;  // Try next address
    }

    // Must be non-blocking for timeout control with poll()
    if (set_nonblocking(fd) != 0) {
      close(fd);
      continue;
    }

    // Copy address and assign target port
    struct sockaddr_storage storage;
    memcpy(&storage, addr->ai_addr, addr->ai_addrlen);
    assign_port((struct sockaddr *)&storage, addr->ai_addrlen, port);

    // Initiate non-blocking connect
    int rc = connect(fd, (struct sockaddr *)&storage, addr->ai_addrlen);
    if (rc == 0) {
      // Rare: connect completed immediately (loopback or cached route)
      snprintf(reason, reason_len, "connect() succeeded");
      close(fd);
      return SCAN_STATE_OPEN;
    }

    // Handle immediate errors
    if (errno != EINPROGRESS) {
      int err = errno;
      close(fd);
      if (err == ECONNREFUSED) {
        // RST packet received - port definitely closed
        snprintf(reason, reason_len, "connection refused");
        return SCAN_STATE_CLOSED;
      }
      continue;  // Other error, try next address
    }

    // EINPROGRESS: Connection in progress, use poll() to wait
    struct pollfd pfd = {
        .fd = fd,
        .events = POLLOUT,  // Wait for socket to become writable
    };

    // Convert timeout to milliseconds for poll()
    int timeout_ms = (int)(timeout * 1000.0);
    if (timeout_ms <= 0) {
      timeout_ms = 1;  // Minimum 1ms
    }

    rc = poll(&pfd, 1, timeout_ms);

    if (rc > 0) {
      // Socket became ready - check actual connection result
      int err = 0;
      socklen_t errlen = sizeof(err);
      if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &errlen) == 0) {
        if (err == 0) {
          // Connection succeeded
          snprintf(reason, reason_len, "connect() succeeded");
          close(fd);
          return SCAN_STATE_OPEN;
        }
        if (err == ECONNREFUSED) {
          // Connection refused (RST received)
          snprintf(reason, reason_len, "connection refused");
          close(fd);
          return SCAN_STATE_CLOSED;
        }
        // Other error (EHOSTUNREACH, ENETUNREACH, etc.)
        snprintf(reason, reason_len, "socket error (%s)", strerror(err));
        close(fd);
        return SCAN_STATE_OPEN_FILTERED;
      }
    } else if (rc == 0) {
      // Timeout: firewall likely dropping packets or host down
      snprintf(reason, reason_len, "connect timeout");
      close(fd);
      return SCAN_STATE_OPEN_FILTERED;
    } else if (errno != EINTR) {
      // poll() error (not a signal interruption)
      snprintf(reason, reason_len, "poll failed (%s)", strerror(errno));
      close(fd);
      return SCAN_STATE_ERROR;
    }

    close(fd);
  }

  // All addresses failed
  if (last_err) {
    snprintf(reason, reason_len, "socket() failed (%s)", strerror(last_err));
  } else {
    snprintf(reason, reason_len, "no reachable address");
  }
  return SCAN_STATE_ERROR;
}

/*
 * Performs a UDP scan on a single port.
 *
 * UDP Scanning Challenges:
 * - UDP is connectionless - no handshake like TCP
 * - Sending a packet doesn't guarantee a response
 * - Most services ignore invalid/empty UDP packets
 * - The only reliable negative signal: ICMP Port Unreachable (Type 3, Code 3)
 *
 * State Determination:
 * - CLOSED: ICMP Port Unreachable received (kernel confirmed port closed)
 * - OPEN: Received UDP response payload (service replied to our probe)
 * - OPEN|FILTERED: No response (port may be open but silent, or filtered)
 *
 * Why "OPEN|FILTERED" instead of definitive states?
 * - Many UDP services silently ignore invalid packets (DNS, NTP, SNMP, etc.)
 * - Firewalls may silently drop packets without sending ICMP errors
 * - Cannot distinguish between: open port (silent), filtered port, or down host
 * - This is a fundamental limitation of UDP scanning
 *
 * ICMP Error Detection:
 * - Linux kernel delivers ICMP errors to connected UDP sockets via SO_ERROR
 * - We use connect() on UDP socket to enable error delivery (doesn't send packets)
 * - POLLERR event indicates pending error; check SO_ERROR to retrieve it
 * - ECONNREFUSED errno corresponds to ICMP Port Unreachable
 *
 * Educational Notes:
 * - connect() on UDP socket doesn't send packets; it just filters incoming packets
 * - SO_ERROR: Pending error associated with socket (doesn't affect errno)
 * - POLLIN: Data available to read (service response)
 * - POLLERR: Error condition (usually ICMP error from kernel)
 */
static scan_state_t udp_attempt(const struct addrinfo *addrs, uint16_t port,
                                double timeout, char *reason,
                                size_t reason_len) {
  const struct addrinfo *addr = NULL;
  int last_err = 0;

  // Try each resolved address
  for (addr = addrs; addr; addr = addr->ai_next) {
    int fd = socket(addr->ai_family, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0) {
      last_err = errno;
      continue;
    }

    // Copy address and assign target port
    struct sockaddr_storage storage;
    memcpy(&storage, addr->ai_addr, addr->ai_addrlen);
    assign_port((struct sockaddr *)&storage, addr->ai_addrlen, port);

    // connect() on UDP: doesn't send packets, but enables ICMP error delivery
    if (connect(fd, (struct sockaddr *)&storage, addr->ai_addrlen) != 0) {
      close(fd);
      continue;
    }

    // Send minimal probe packet (many services ignore this)
    unsigned char payload = 0;
    ssize_t sent = send(fd, &payload, sizeof(payload), 0);
    if (sent < 0) {
      int err = errno;
      close(fd);
      if (err == ECONNREFUSED) {
        // ICMP Port Unreachable delivered immediately (cached)
        snprintf(reason, reason_len, "ICMP Port Unreachable");
        return SCAN_STATE_CLOSED;
      }
      continue;
    }

    // Wait for response or ICMP error
    struct pollfd pfd = {
        .fd = fd,
        .events = POLLIN | POLLERR,  // Data or error
    };

    int timeout_ms = (int)(timeout * 1000.0);
    if (timeout_ms <= 0) {
      timeout_ms = 1;
    }

    int rc = poll(&pfd, 1, timeout_ms);

    if (rc == 0) {
      // Timeout: No response, no ICMP error
      // Port may be open (silent service), filtered, or host down
      snprintf(reason, reason_len, "no reply (no ICMP)");
      close(fd);
      return SCAN_STATE_OPEN_FILTERED;
    }

    if (rc < 0) {
      close(fd);
      continue;  // poll() error, try next address
    }

    // Check for ICMP error (POLLERR)
    if (pfd.revents & POLLERR) {
      // Kernel received ICMP error - check SO_ERROR for details
      int err = 0;
      socklen_t errlen = sizeof(err);
      if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &errlen) == 0) {
        close(fd);
        if (err == ECONNREFUSED) {
          // ICMP Type 3 Code 3: Port Unreachable
          snprintf(reason, reason_len, "ICMP Port Unreachable");
          return SCAN_STATE_CLOSED;
        }
        // Other ICMP errors (host unreachable, network unreachable, etc.)
        snprintf(reason, reason_len, "socket error (%s)", strerror(err));
        return SCAN_STATE_OPEN_FILTERED;
      }
    }

    // Check for application data (POLLIN)
    if (pfd.revents & POLLIN) {
      // Service sent a UDP response - port is definitely open
      unsigned char buffer[256];
      ssize_t received = recv(fd, buffer, sizeof(buffer), 0);
      close(fd);
      if (received >= 0) {
        snprintf(reason, reason_len, "received UDP payload");
        return SCAN_STATE_OPEN;
      }
      // recv() failed - check if it's an ICMP error
      if (errno == ECONNREFUSED) {
        snprintf(reason, reason_len, "ICMP Port Unreachable");
        return SCAN_STATE_CLOSED;
      }
    }

    close(fd);
  }

  // All addresses failed
  if (last_err) {
    snprintf(reason, reason_len, "socket() failed (%s)", strerror(last_err));
  } else {
    snprintf(reason, reason_len, "no reachable address");
  }
  return SCAN_STATE_ERROR;
}

static scan_state_t perform_scan(const scanner_options_t *opts,
                                 scan_proto_t proto, uint16_t port,
                                 rate_limiter_t *limiter, char *reason,
                                 size_t reason_len) {
  scan_state_t state = SCAN_STATE_ERROR;
  // Each retry is paced through the shared limiter so all workers respect the
  // global rate cap.
  for (int attempt = 0; attempt < opts->retries; ++attempt) {
    rate_limiter_wait(limiter);
    if (proto == SCAN_PROTO_TCP) {
      state = tcp_attempt(opts->addrs, port, opts->timeout_seconds, reason,
                          reason_len);
    } else {
      state = udp_attempt(opts->addrs, port, opts->timeout_seconds, reason,
                          reason_len);
    }
    if (state == SCAN_STATE_OPEN || state == SCAN_STATE_CLOSED) {
      break;
    }
  }
  return state;
}

static int dequeue_task(task_queue_t *queue, scan_task_t *out_task) {
  int have_task = 0;
  pthread_mutex_lock(&queue->mutex);
  if (queue->next < queue->count) {
    *out_task = queue->tasks[queue->next++];
    have_task = 1;
  }
  pthread_mutex_unlock(&queue->mutex);
  return have_task;
}

static void *worker_main(void *arg) {
  worker_ctx_t *ctx = (worker_ctx_t *)arg;
  scan_task_t task;
  while (dequeue_task(ctx->queue, &task)) {
    scan_result_t *result = &ctx->results->items[task.result_index];
    result->port = task.port;
    result->proto = task.proto;
    const char *service = guess_service(task.proto, task.port);
    snprintf(result->service, sizeof(result->service), "%s", service);
    scan_state_t state =
        perform_scan(ctx->opts, task.proto, task.port, ctx->limiter,
                     result->reason, sizeof(result->reason));
    result->state = state;
    if (result->reason[0] == '\0') {
      snprintf(result->reason, sizeof(result->reason), "unknown");
    }
  }
  return NULL;
}

int run_scanner(scanner_options_t *opts, scan_result_set_t *out_results) {
  size_t total = 0;
  if (opts->enable_tcp) {
    total += opts->tcp_ports.count;
  }
  if (opts->enable_udp) {
    total += opts->udp_ports.count;
  }
  out_results->items = calloc(total, sizeof(scan_result_t));
  if (!out_results->items) {
    fprintf(stderr, "Out of memory allocating result set.\n");
    return -1;
  }
  out_results->count = total;

  task_queue_t queue;
  if (task_queue_init(&queue, total) != 0) {
    fprintf(stderr, "Failed to init task queue.\n");
    free_results(out_results);
    return -1;
  }

  size_t index = 0;
  if (opts->enable_tcp) {
    for (size_t i = 0; i < opts->tcp_ports.count; ++i, ++index) {
      queue.tasks[index].proto = SCAN_PROTO_TCP;
      queue.tasks[index].port = opts->tcp_ports.values[i];
      // Result slots mirror queue order so worker threads can write without
      // additional locks.
      queue.tasks[index].result_index = index;
    }
  }
  if (opts->enable_udp) {
    for (size_t i = 0; i < opts->udp_ports.count; ++i, ++index) {
      queue.tasks[index].proto = SCAN_PROTO_UDP;
      queue.tasks[index].port = opts->udp_ports.values[i];
      // Maintain sequential indices even as we mix protocols.
      queue.tasks[index].result_index = index;
    }
  }

  rate_limiter_t limiter;
  if (rate_limiter_init(&limiter, opts->rate_per_second) != 0) {
    fprintf(stderr, "Failed to init rate limiter.\n");
    task_queue_destroy(&queue);
    free_results(out_results);
    return -1;
  }

  int worker_count = opts->concurrency;
  if (worker_count < 1) {
    worker_count = 1;
  }
  pthread_t *threads = calloc((size_t)worker_count, sizeof(pthread_t));
  if (!threads) {
    fprintf(stderr, "Out of memory creating workers.\n");
    rate_limiter_destroy(&limiter);
    task_queue_destroy(&queue);
    free_results(out_results);
    return -1;
  }

  worker_ctx_t ctx = {
      .opts = opts,
      .addrs = opts->addrs,
      .queue = &queue,
      .results = out_results,
      .limiter = &limiter,
  };
  for (int i = 0; i < worker_count; ++i) {
    if (pthread_create(&threads[i], NULL, worker_main, &ctx) != 0) {
      fprintf(stderr, "Failed to create worker thread.\n");
      worker_count = i;
      break;
    }
  }
  for (int i = 0; i < worker_count; ++i) {
    pthread_join(threads[i], NULL);
  }

  free(threads);
  rate_limiter_destroy(&limiter);
  task_queue_destroy(&queue);
  return 0;
}

void free_results(scan_result_set_t *results) {
  free(results->items);
  results->items = NULL;
  results->count = 0;
}
