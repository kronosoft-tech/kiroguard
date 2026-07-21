# KiroGuard - Product Overview

KiroGuard is an MCP (Model Context Protocol) server that acts as a preventive guard before code reaches production. It exposes multiple analysis tools over JSON-RPC 2.0 via stdio or HTTP+SSE transports.

## Core Modules

- **Env-Guard** (`envguard/scan`): Scans diffs for hardcoded secrets, blocks commits containing them, and optionally migrates secrets to AWS Secrets Manager or SSM Parameter Store.
- **Vuln-Scanner** (`vulnscanner`): Parses dependency manifests and checks them against the OSV vulnerability database.
- **Clean-Arch** (`cleanarch/analyze`): Performs read-only AST-based architecture linting by building import graphs and evaluating them against configurable dependency rules.
- **FinOps Guardrail** (`finops/analyze`): Detects expensive cloud patterns (N+1 queries, unpaginated scans, misconfigured Lambdas) and estimates monthly cost impact.

## LLM Integration

Uses AWS Bedrock (Claude) as the primary LLM backend with a heuristic fallback. LLM is used for richer explanations in vuln-scanner and finops modules, not for core detection logic.

## Configuration

YAML-based configuration with sensible defaults. All modules work out of the box without a config file. AWS credentials are only needed for Bedrock LLM and secret migration features.
