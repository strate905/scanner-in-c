/*
 * output.c - Output Formatting Module
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
 * This module handles result presentation in two formats:
 * - Markdown tables: Human-readable, suitable for documentation/reports
 * - JSON: Machine-parseable, suitable for automation/integration
 *
 * Educational concepts demonstrated:
 * - String formatting with printf family functions
 * - Manual JSON generation without libraries (educational approach)
 * - Character escaping for JSON string safety
 * - Enum-to-string conversion patterns
 */

#include "scanner.h"

#include <stdio.h>
#include <string.h>

/*
 * Converts protocol enum to human-readable string.
 * Simple mapping, but demonstrates enum-to-string pattern.
 */
static const char *proto_to_string(scan_proto_t proto) {
  return proto == SCAN_PROTO_TCP ? "TCP" : "UDP";
}

/*
 * Converts scan state enum to string representation.
 *
 * State Meanings:
 * - "open": Port is accepting connections
 * - "closed": Port actively refused connection (RST for TCP, ICMP for UDP)
 * - "open|filtered": Cannot determine (timeout, no response)
 * - "error": Scan failed due to system/network error
 *
 * Note: Always include default case in switch to handle unexpected values.
 */
static const char *state_to_string(scan_state_t state) {
  switch (state) {
  case SCAN_STATE_OPEN:
    return "open";
  case SCAN_STATE_CLOSED:
    return "closed";
  case SCAN_STATE_OPEN_FILTERED:
    return "open|filtered";
  case SCAN_STATE_ERROR:
  default:
    return "error";
  }
}

static void print_markdown(const scanner_options_t *opts,
                           const scan_result_set_t *results) {
  const char *target_label =
      opts->display_target ? opts->display_target : opts->target;
  printf("# Scan Results for %s\n\n", target_label);
  printf("| Port | Proto | State | Service | Reason |\n");
  printf("|-----:|:-----:|:------|:--------|:-------|\n");
  for (size_t i = 0; i < results->count; ++i) {
    const scan_result_t *res = &results->items[i];
    printf("| %5u | %5s | %-12s | %-8s | %s |\n", res->port,
           proto_to_string(res->proto), state_to_string(res->state),
           res->service, res->reason);
  }
}

/*
 * Prints a JSON-escaped string.
 *
 * JSON String Escaping Rules (RFC 8259):
 * - Quotation mark (") must be escaped as \"
 * - Backslash (\) must be escaped as \\
 * - Control characters (0x00-0x1F) must be escaped
 *   - Newline (\n) -> \\n
 *   - Carriage return (\r) -> \\r
 *   - Tab (\t) -> \\t
 *
 * Educational Notes:
 * - We handle the minimum required escapes for safety
 * - Production code might use libraries (e.g., json-c, jansson)
 * - This manual approach demonstrates the actual requirements
 * - putchar() is slightly more efficient than printf("%c", ...)
 * - fputs() outputs multiple characters at once (faster than putchar loop)
 *
 * Why escape these specific characters?
 * - " terminates strings prematurely if not escaped
 * - \ is the escape character itself, must be doubled
 * - Control characters break JSON parsers and displays
 */
static void print_json_string(const char *value) {
  putchar('"');  // Opening quote
  if (value) {
    for (const char *p = value; *p; ++p) {
      switch (*p) {
      case '"':
        fputs("\\\"", stdout);  // Escape quotation mark
        break;
      case '\\':
        fputs("\\\\", stdout);  // Escape backslash
        break;
      case '\n':
        fputs("\\n", stdout);   // Escape newline
        break;
      case '\r':
        fputs("\\r", stdout);   // Escape carriage return
        break;
      case '\t':
        fputs("\\t", stdout);   // Escape tab
        break;
      default:
        putchar(*p);            // Normal character, no escaping
        break;
      }
    }
  }
  putchar('"');  // Closing quote
}

/*
 * Prints scan results as JSON array.
 *
 * JSON Structure:
 * [
 *   {
 *     "port": 80,
 *     "proto": "TCP",
 *     "state": "open",
 *     "service": "http",
 *     "reason": "connect() succeeded"
 *   },
 *   ...
 * ]
 *
 * Educational Notes on JSON Formatting:
 * - Arrays: [element, element, ...] (comma-separated, no trailing comma)
 * - Objects: {"key": value, ...} (comma-separated, no trailing comma)
 * - Numbers: output directly without quotes
 * - Strings: must be quoted and escaped
 * - Trailing comma issue: Last element should NOT have comma
 *   Solution: Use conditional (i + 1 == count) ? "" : ","
 *
 * Design Choice:
 * - We build JSON manually with printf instead of using a library
 * - This is educational: students see the actual JSON syntax requirements
 * - Production code would typically use json-c, jansson, or cJSON
 */
static void print_json(const scanner_options_t *opts,
                       const scan_result_set_t *results) {
  (void)opts;  // Unused parameter (opts might be used in future for metadata)

  printf("[\n");  // Start JSON array

  for (size_t i = 0; i < results->count; ++i) {
    const scan_result_t *res = &results->items[i];

    printf("  {\n");  // Start object

    // Port: numeric value, no quotes needed
    printf("    \"port\": %u,\n", res->port);

    // Proto: string value, needs quotes and escaping
    printf("    \"proto\": ");
    print_json_string(proto_to_string(res->proto));
    printf(",\n");

    // State: string value
    printf("    \"state\": ");
    print_json_string(state_to_string(res->state));
    printf(",\n");

    // Service: string value (may be empty)
    printf("    \"service\": ");
    print_json_string(res->service);
    printf(",\n");

    // Reason: string value (last field, no trailing comma)
    printf("    \"reason\": ");
    print_json_string(res->reason);
    printf("\n");

    // End object, add comma unless last element
    printf("  }%s\n", (i + 1 == results->count) ? "" : ",");
  }

  printf("]\n");  // End JSON array
}

void emit_results(const scanner_options_t *opts,
                  const scan_result_set_t *results) {
  if (opts->output_json) {
    print_json(opts, results);
  } else {
    print_markdown(opts, results);
  }
}
