# KiroGuard

<pre>
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║   ██████╗ ███████╗████████╗██████╗  ██████╗     ██████╗  █████╗  ║
║   ██╔══██╗██╔════╝╚══██╔══╝██╔══██╗██╔═══██╗    ██╔══██╗██╔══██╗ ║
║   ██████╔╝█████╗     ██║   ██████╔╝██║   ██║    ██████╔╝███████║ ║
║   ██╔══██╗██╔══╝     ██║   ██╔══██╗██║   ██║    ██╔══██╗██╔══██║ ║
║   ██║  ██║███████╗   ██║   ██║  ██║╚██████╔╝    ██║  ██║██║  ██║ ║
║   ╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝     ╚═╝  ╚═╝╚═╝  ╚═╝ ║
║                        ███████╗ ██████╗ ██╗                         ║
║                        ██╔════╝██╔═══██╗██╗                         ║
║                        ███████╗██║   ██║██║                         ║
║                        ╚════██║██║▄▄ ██║██║                         ║
║                        ███████║╚██████║███████╗                    ║
║                        ╚══════╝ ╚══▀▀═╝╚══════╝                    ║
║                                                                   ║
║              ███╗   ███╗ ██████╗ ██████╗ ██╗   ██╗██╗     ███████╗  ║
║              ████╗ ████║██╔═══██╗██╔══██╗██║   ██║██║     ██╔════╝  ║
║              ██╔████╔██║██║   ██║██████╔╝██║   ██║██║     █████╗    ║
║              ██║╚██╔╝██║██║   ██║██╔══██╗██║   ██║██║     ██╔══╝    ║
║              ██║ ╚═╝ ██║╚██████╔╝██║  ██║╚██████╔╝███████╗███████╗  ║
║              ╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚══════╝  ║
║                                                                   ║
║                         M C P   S E R V E R                       ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
</pre>

<p align="center">
  <a href="https://pkg.go.dev/github.com/luiferdev/kiroguard">
    <img src="https://pkg.go.dev/badge/github.com/luiferdev/kiroguard.svg" alt="Go Reference">
  </a>
  <a href="https://github.com/luiferdev/kiroguard/actions/workflows/test.yml">
    <img src="https://github.com/luiferdev/kiroguard/actions/workflows/test.yml/badge.svg" alt="Tests">
  </a>
  <a href="https://github.com/luiferdev/kiroguard/releases">
    <img src="https://img.shields.io/github/v/release/luiferdev/kiroguard?include_prereleases&sort=semver" alt="Release">
  </a>
  <a href="https://goreportcard.com/report/github.com/luiferdev/kiroguard">
    <img src="https://goreportcard.com/badge/github.com/luiferdev/kiroguard" alt="Go Report Card">
  </a>
  <a href="https://opensource.org/licenses/MIT">
    <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License: MIT">
  </a>
  <a href="https://github.com/luiferdev/kiroguard">
    <img src="https://img.shields.io/github/stars/luiferdev/kiroguard" alt="Stars">
  </a>
</p>

---

## What is KiroGuard?

**KiroGuard** is an MCP (Model Context Protocol) server that acts as a preventive guard before code reaches production. It exposes multiple security, quality, and cost analysis tools over JSON-RPC 2.0.

Built in **Go** for speed and reliability, KiroGuard runs as a single binary and supports two transport modes:
- **stdio**: For integration with git hooks, editors, and CLI tools
- **HTTP + SSE**: For remote connections and web-based workflows

---

## Features

### 🛡️ Env-Guard (Secret Detection & Migration)
- Regex-based detection of hardcoded secrets (AWS keys, API tokens, PEM headers, DB DSNs, JWTs)
- `.envguardignore` support with glob and regex patterns
- Automatic migration to AWS Secrets Manager or SSM Parameter Store
- Generates safe replacement snippets without leaking original secrets

### 🔍 Vuln-Scanner (Dependency Security)
- Parses npm (`package.json`, `package-lock.json`) and pip (`requirements.txt`) manifests
- Batch vulnerability lookup via [OSV.dev](https://osv.dev/) API (free, no API key required)
- Human-readable CVE explanations powered by AWS Bedrock LLM

### 🏗️ Clean-Arch (Architecture Linting)
- AST-based import graph construction using Go's `go/parser`
- Configurable architecture rules (YAML) with glob pattern matching
- Default layered architecture rules (domain ↛ infrastructure ↛ presentation)
- **Read-only operation** — never modifies source files

### 💰 FinOps Guardrail (Cost Estimation)
- Pre-deploy pattern detection:
  - N+1 query loops
  - Unpaginated DynamoDB scans
  - Lambdas without memory/timeout configuration
- Monthly cost estimation with documented formulas based on AWS public pricing
- Concrete dollar amounts (e.g., "$73/month at 1000 req/hr")

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        KiroGuard MCP Server                     │
├─────────────────────────────────────────────────────────────────┤
│  Transport Layer                                                │
│  ┌─────────────┐  ┌─────────────┐                               │
│  │   stdio     │  │  HTTP + SSE │                               │
│  └──────┬──────┘  └──────┬──────┘                               │
│         │                │                                       │
│         └────────┬───────┘                                       │
│                  ▼                                               │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │              JSON-RPC 2.0 Dispatcher                      │  │
│  └────────────────────────┬─────────────────────────────────┘  │
│                           │                                      │
│  ┌────────────┬───────────┼────────────┬──────────────┐        │
│  ▼            ▼           ▼            ▼              ▼        │
│ ┌────────┐ ┌────────┐ ┌──────────┐ ┌──────────┐ ┌─────────┐   │
│ │ Env-   │ │ Vuln   │ │ Clean    │ │ FinOps   │ │   LLM   │   │
│ │ Guard  │ │Scanner │ │  Arch    │ │ Guardrail│ │ Backend │   │
│ └────────┘ └────────┘ └──────────┘ └──────────┘ └─────────┘   │
│                                                                 │
│  AWS Services (optional)                                        │
│  ┌──────────────┬───────────────┬─────────────────┐            │
│  │ Bedrock      │ Secrets Mgr   │  SSM Parameter  │            │
│  │ (LLM)        │ (migration)   │  Store          │            │
│  └──────────────┴───────────────┴─────────────────┘            │
└─────────────────────────────────────────────────────────────────┘
```

---

## Installation

```bash
# Clone the repository
git clone https://github.com/luiferdev/kiroguard.git
cd kiroguard

# Build the binary
go build -o kiroguard .

# Or install globally
go install .
```

---

## Quick Start

### Stdio Mode (default)

```bash
# Run with stdio transport (for MCP clients)
go run .
```

### SSE Mode (HTTP + Server-Sent Events)

```bash
# Run with SSE transport on custom port
go run . -transport sse -port 8080
```

### With Configuration File

```bash
# Run with custom config
go run . -config config.yaml -log-format json
```

---

## Configuration

KiroGuard works out of the box with sensible defaults. For customization, create a `config.yaml`:

```yaml
transport:
  type: stdio        # stdio or sse
  port: 3000         # HTTP port for SSE

llm:
  region: us-east-1  # AWS region for Bedrock
  model-id: anthropic.claude-3-sonnet-20240229-v1:0

envguard:
  ignore-file: .envguardignore

cleanarch:
  rules-file: cleanarch-rules.yaml

finops:
  default-rph: 1000  # Default requests per hour
```

### CLI Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-transport` | `stdio` | Transport type: `stdio` or `sse` |
| `-port` | `3000` | HTTP port for SSE transport |
| `-config` | `""` | Path to YAML configuration file |
| `-log-format` | `text` | Log output format: `text` or `json` |

---

## MCP Tools

Once running, KiroGuard exposes these tools via JSON-RPC 2.0:

| Tool | Description |
|------|-------------|
| `envguard/scan` | Scan code for hardcoded secrets |
| `vulnscanner/scan` | Check dependencies for known CVEs |
| `cleanarch/analyze` | Analyze code architecture violations |
| `finops/analyze` | Estimate cloud cost impact |

---

## Integrations

### Git Pre-commit Hook

```bash
# .git/hooks/pre-commit
#!/bin/bash
go run . -transport stdio
```

### VS Code

Configure the MCP client to connect to KiroGuard's SSE endpoint.

---

## Development

```bash
# Run all tests
go test ./...

# Run tests with verbose output
go test -v ./...

# Run tests with race detection
go test -race ./...

# Tidy dependencies
go mod tidy
```

---

## Tech Stack

- **Language**: Go 1.26.5
- **Protocol**: JSON-RPC 2.0
- **AWS SDK**: aws-sdk-go-v2
- **Config**: YAML (gopkg.in/yaml.v3)
- **Logging**: Standard library log/slog

---

## License

MIT License - see [LICENSE](LICENSE) for details.

---

## Contributing

Contributions are welcome! Please open an issue or submit a PR.

---

<p align="center">
  <sub>Built with 🔥 by <a href="https://github.com/orgs/kronosoft-tech">kronosoft</a></sub>
</p>
```

---

