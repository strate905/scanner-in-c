# Educational Network Scanner in C

**An educational port scanner implementation in portable C11** designed for learning network programming concepts on Linux systems. This project demonstrates TCP connect scans, UDP probes with ICMP handling, and produces both human-readable Markdown tables and machine-parseable JSON output.

All observable behavior, CLI flags, and formatting expectations are defined in `SPECIFICATIONS.md`. The README focuses on helping you set up a local build, run the scanner, and exercise the tests.

## Setup

- Linux environment with glibc (Ubuntu 22.04+ or similar).
- Toolchain: `clang` (recommended) or `gcc`, GNU `make`, and POSIX headers (`pthread`, `netdb`, `arpa/inet`).
- Optional: `valgrind` for leak checks, `clang-format` (LLVM style) for consistent formatting.

Clone and enter the repository:

```bash
git clone https://github.com/<your-org>/scanner-in-c.git
cd scanner-in-c
```

If your distribution does not ship `clang` by default, install the build dependencies (example for Debian/Ubuntu):

```bash
sudo apt-get update
sudo apt-get install -y clang make build-essential valgrind
```

## Build

### Using the Makefile (preferred)

The default target compiles all sources into `build/scanner`:

```bash
make build
```

You can override the compiler and flags when invoking `make`:

```bash
CC=gcc CFLAGS="-O2 -pipe" make build
```

Additional convenience targets:

- `make run ARGS="--tcp 22,80 scan.me"` – build (if needed) then execute the scanner with the provided arguments.
- `make clean` – remove `build/` binaries.
- `make test` – compile and execute CLI parsing tests under `tests/`.

### Manual compilation

If you prefer invoking the compiler directly:

```bash
mkdir -p build
clang -std=c11 -Wall -Wextra -pedantic src/*.c -o build/scanner
```

This mirrors the flags used by the Makefile.

## Run

The scanner accepts both TCP and UDP port specifications and can emit Markdown or JSON output.

```
./build/scanner [--tcp PORTS] [--udp PORTS] [--timeout SECONDS]
                [--retries N] [--concurrency N] [--rate PPS]
                [--no-dns] [--json] <target>
```

- Targets default to `127.0.0.1` when omitted: `./build/scanner --tcp 22,80`.
- Combine comma-delimited ports and inclusive ranges: `--udp 53,67-69`.
- Add `--json` to emit machine-friendly JSON instead of Markdown tables.
- DNS lookups are enabled by default; disable with `--no-dns` to keep output numeric.
- Respect the educational intent—scan only hosts you are authorized to assess.

Example session:

```bash
make build
./build/scanner --tcp 22,80,443 --udp 53 scan.me.org
```

## Test & Validate

- `make test` – builds `build/tests/test_cli` and executes the CLI-focused unit tests.
- `valgrind ./build/scanner --tcp 80 localhost` – check for memory leaks and ensure sockets are cleaned up (required before merging networking changes).
- `clang-format -i src/*.c include/*.h` – apply the repository formatting style.

## Project Layout

- `src/` – scanner implementation (`main.c`, `cli.c`, `scanner.c`, `output.c`).
- `include/` – public headers (`scanner.h`).
- `tests/` – C11 tests (`tests/test_cli.c` plus shared helpers in `tests/support/`).
- `assets/` – curated fixtures (e.g., sample port lists).
- `SPECIFICATIONS.md` – authoritative behavior and output contract for the CLI.

## Limitations & Roadmap

- Running without sufficient privileges (containers, sandboxes) may block socket operations: expect errors such as `socket() failed (Operation not permitted)`.
- Future improvements: expand automated coverage, refine UDP heuristics, tune concurrency controls, and publish sample output tables for documentation.

## License

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.
