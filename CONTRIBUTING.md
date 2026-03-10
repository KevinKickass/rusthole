# Contributing to rusthole

Thanks for your interest in contributing!

## Getting Started

1. Fork the repo and clone your fork
2. `cargo build` to verify everything compiles
3. `cargo test` to run the test suite
4. Create a branch for your changes

## Development

```bash
cargo build                  # debug build
cargo build --release        # release build
cargo test                   # run tests
cargo clippy                 # lint
cargo fmt                    # format
```

Running locally requires root for port 53:

```bash
sudo ./target/release/rusthole
```

## Pull Requests

- One logical change per PR
- Run `cargo fmt` and `cargo clippy` before submitting
- Add tests for new functionality
- Keep commits clean and descriptive
- CI must pass (check, fmt, clippy, test, multi-target build)

## Architecture

```
src/
├── main.rs              # Entry point, config loading, server startup
├── config.rs            # TOML config parsing
├── db.rs                # SQLite query log and stats
├── dns_rewrite.rs       # DNS rewrite rules
├── group_policy.rs      # Client group policies
├── schedule.rs          # Scheduled tasks
├── upstream_health.rs   # Upstream health monitoring
├── api/                 # REST API (axum)
├── blocklist/           # Blocklist parsing, matching, wildcard support
├── dhcp/                # Optional DHCP server
├── dns/                 # DNS server (UDP + TCP), query handling
└── web/                 # Embedded web dashboard
```

## Reporting Issues

- Search existing issues first
- Include your OS, architecture, and rusthole version
- For DNS issues: include the domain and expected behavior

## Code Style

- Follow standard Rust conventions
- No `unwrap()` in production code paths — use proper error handling
- Keep dependencies minimal

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
