# Introduction

Proxelar is a scriptable local traffic workbench written in Rust. It sits between a client and an upstream service so you can inspect, intercept, replay, and modify HTTP, HTTPS, and WebSocket traffic.

It is aimed at development and debugging workflows: API inspection, local service mocking, request/response rewriting, WebSocket debugging, and repeatable traffic transforms without changing the application under test.

## What can it do?

- **Inspect traffic** — see every request and response in real time, including headers and bodies
- **Intercept HTTPS** — automatic CA certificate generation and per-host certificate minting
- **Modify traffic with scripts and rules** — hot-reload Lua hooks or declare maps, redirects, mocks, and header changes
- **Package repeatable extensions** — verify, install, discover, and run versioned integrity-checked Lua addons
- **Seven capture modes** — forward, reverse, transparent, WireGuard, SOCKS5, DNS, and fixed-target UDP
- **Four interfaces** — interactive TUI, plain terminal output, web GUI, or headless REST API
- **Inspect WebSockets** — capture WebSocket connections and browse individual frames
- **Keep portable sessions** — reload native captures or exchange HAR, curl, and raw HTTP artifacts with default secret redaction

## What is it not?

Proxelar is not trying to replace a mature security suite. If you need scanning, collaborative testing, a large pre-existing addon inventory, or end-to-end HTTP/2/HTTP/3 interception, use a tool built for that workflow. Proxelar is deliberately smaller: a local, scriptable proxy that is easy to install, run, and automate.

## Architecture

Proxelar is built as a three-crate Rust workspace:

- **`proxelar-cli`** — the CLI binary with terminal, TUI, web, and API interfaces
- **`proxyapi`** — the core proxy engine, usable as a standalone library
- **`proxyapi_models`** — shared request/response data types

The proxy engine is built on [hyper](https://hyper.rs) 1.x, [rustls](https://github.com/rustls/rustls) 0.23, and [tokio](https://tokio.rs). HTTPS interception uses OpenSSL for certificate generation and rustls for TLS termination. Lua scripting is powered by [mlua](https://github.com/khvzak/mlua) with a vendored Lua 5.4.
