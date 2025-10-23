/*
 * main.c - Entry Point
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
 * This is the main orchestration module that ties together all components:
 * 1. CLI parsing (cli.c) - Validates arguments and resolves target
 * 2. Scanning engine (scanner.c) - Multi-threaded port scanning
 * 3. Output formatting (output.c) - Markdown or JSON results
 *
 * Educational concepts demonstrated:
 * - Clean error handling with early returns
 * - Resource cleanup (always free allocated memory, even on error paths)
 * - Return code conventions (EXIT_SUCCESS = 0, EXIT_FAILURE = 1)
 * - Zero-initialization of structures
 * - Separation of concerns (each module has single responsibility)
 */

#include "scanner.h"

#include <stdio.h>
#include <stdlib.h>

/*
 * Main entry point.
 *
 * Program Flow:
 * 1. Parse command-line arguments and resolve DNS
 * 2. Build task queue and spawn worker threads
 * 3. Workers perform scans and populate result array
 * 4. Format and print results (Markdown or JSON)
 * 5. Clean up all allocated resources
 *
 * Error Handling Philosophy:
 * - All functions return 0 on success, non-zero on error
 * - parse_options() returns >0 for --help (not an error)
 * - Always clean up resources before returning, even on error paths
 * - This prevents memory leaks detected by valgrind
 *
 * Educational Notes on Resource Management:
 * - Zero-initialization: {0} sets all fields to zero/NULL
 * - RAII pattern: Each module provides init/free pairs
 * - Cleanup on error paths: Must free partial allocations
 * - tools like valgrind verify proper cleanup
 */
int main(int argc, char **argv) {
  // Zero-initialize structures (all pointers NULL, counts 0)
  scanner_options_t options = {0};
  scan_result_set_t results = {0};

  // Phase 1: Parse and validate command-line arguments
  int parse_rc = parse_options(argc, argv, &options);
  if (parse_rc != 0) {
    // parse_rc > 0: User requested --help (success)
    // parse_rc < 0: Parse error (failure)
    free_options(&options);
    return parse_rc > 0 ? EXIT_SUCCESS : EXIT_FAILURE;
  }

  // Phase 2: Execute port scans with worker thread pool
  if (run_scanner(&options, &results) != 0) {
    // Scan failed - clean up both options and results
    free_results(&results);
    free_options(&options);
    return EXIT_FAILURE;
  }

  // Phase 3: Display results in requested format
  emit_results(&options, &results);

  // Phase 4: Clean up all allocated resources
  // Must free in reverse order of allocation
  free_results(&results);
  free_options(&options);

  return EXIT_SUCCESS;
}
