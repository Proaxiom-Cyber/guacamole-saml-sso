# Guacamole deployment installer

<!-- impeccable:product-schema 1 -->

## Platform

Terminal application, accessed locally or over SSH. It is not a web application.

## Users

IT administrators who understand DNS, Cloudflare, and Entra. They need to deploy
Guacamole quickly without reading source code or cloning a repository.

## Product Purpose

Install one Guacamole deployment on a Rocky Linux 10 AMD64 host. Support temporary
and durable deployments, resumable setup, backup, recovery, and owned-resource teardown.

## Operating Context

Administrators often work through a normal 80-column SSH terminal. Microsoft
authorization takes place in a separate browser. Some tenants block device codes.
The binary must run without a language interpreter on the deployment host.

## Capabilities and Constraints

- Keep deployment progress and resource ownership outside the source repository.
- Preserve pre-existing and shared resources. Ask before changing them.
- Retain data by default during teardown.
- Keep credentials out of state, logs, and terminal history.
- Generate certificate keys on the deployment host. A TPM key remains non-exportable.
- Combine administrator device sign-in with automatic certificate registration.
- Provide manual app registration when device sign-in is unavailable.
- Keep plain terminal output and unattended operation supported.
- Present clear status, timestamps, recovery actions, and a session log location.

## Evidence on Hand

The approved product decisions are in docs/v1-specification.md. Existing code and
operator screenshots show the current installer. Preview data must be labelled as a demo.

## Product Principles

- Make the next action clear.
- Show progress without making the operator read the full transcript.
- Explain a choice by its effect on the deployment.
- Report failures with retained work and a recovery action.
- Show only progress that the installer has measured.
