# Scanner Specifications

This document sets the authoritative contract for the Linux C port scanner. Keep implementation, tests, and docs aligned with these requirements.

## Purpose
- Deliver a readable educational scanner that still reflects real TCP/UDP behaviors.
- Operate entirely with unprivileged POSIX sockets and pthreads.
- Provide Markdown output for humans and a JSON mode for automation.

## Command-Line Interface
- Binary name: `scanner`.
- Usage pattern:
  ```
  scanner [--tcp PORTS] [--udp PORTS] [--timeout SECONDS]
          [--retries N] [--concurrency N] [--rate PPS]
          [--no-dns] [--json] <target>
  ```
- `<target>` accepts hostnames or IPv4/IPv6 literals; default to `127.0.0.1`.
- Flags:
  - `--tcp`, `--udp`: comma-separated ports with optional inclusive ranges (`22,80,8000-8100`).
  - `--timeout`: per-attempt timeout in seconds.
  - `--retries`: attempts per port (default 1, max 10).
  - `--concurrency`: worker threads (default 32).
  - `--rate`: probes per second; zero disables throttling.
  - `--json`: emit JSON instead of Markdown.
  - `--no-dns`: disable hostname resolution; target must be numeric.

## Default Scan Set
- TCP ports: `80, 443, 22, 21, 25, 23, 53, 110, 135, 139, 143, 445, 3389, 3306, 8080, 5900, 993, 995, 465, 587, 111, 2049, 1025, 1723, 554`
- UDP ports: `53, 123, 161, 500, 1900`

## Scanning Techniques
- **TCP**: Perform unprivileged `connect()` scans; report `open` on success, `closed` on refusal, and `open|filtered` on timeout.
- **UDP**: Send minimalist datagrams; classify ICMP Type 3 Code 3 as `closed`, application replies as `open`, and silence as `open|filtered`.
- Apply retry counts, per-attempt timeout, and rate limiting consistently across protocols.

## Resolution & Target Handling
- Resolve DNS unless `--no-dns` is present.
- When resolution succeeds, show both the original input and the numeric address.
- Support IPv4 and IPv6 endpoints without additional flags.

## Output Format
- Default view is a Markdown table:
  ```
  | Port | Proto | State | Service | Reason |
  ```
- Populate `State`, `Service`, and `Reason` fields with concise explanations (e.g., `connect() succeeded`, `ICMP Port Unreachable`).
- The JSON option mirrors these fields per record for machine consumption.

## Educational Notes
- Explain UDP ambiguity in `--help` text.
- Keep modules focused (`cli`, `scanner`, `output`) so readers can trace the flow from arguments to reports.
