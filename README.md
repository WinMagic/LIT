We introduce a new approach that unifies login and session protection by asserting identity assurance at the transaction level. This innovation removes the historical split between authentication and session security, enabling authentication less Zero Trust and dramatically reducing IAM cost and complexity.

# LIT — Live Identity in Transaction

LIT is an **open specification** for a **continuous, cryptographic identity signal** delivered at the **transaction level**, with **zero user interaction**.

- **LIT (Live Identity in Transaction):** An identity signal bound to a verified human and a verified endpoint, emitted continuously for each transaction.
- **Live Key Engine (LKE):** WinMagic’s endpoint component that generates and governs the **Live Key**, evaluates conditions (user presence, environment, policy), and **emits LIT**. *LKE is proprietary; the LIT spec and public Live Key semantics are open.*

This repository contains:
- **Specifications** for LIT
- **Public semantics** for Live Key (definition and attestation format)
- **Reference client/server examples** (minimal, for learning)
- **Developer SDK stubs** (JS, Python, Go)

> **Goal:** Enable an Internet where each transaction carries **verifiable, policy‑bound identity**—without prompts, passwords, or fragile tokens.

## Why LIT?

Authentication today is dominated by **logins**, **tokens**, and **cookies**—mechanisms not designed for continuous, transaction-level identity. Attackers exploit this gap (token theft, AiTM, session hijack).

**LIT changes the posture**:
- **Continuous**: identity is asserted across the session, not just at login.
- **Bound**: to a verified person and a verified endpoint.
- **Policy-governed**: available only when defined conditions are met.
- **Zero user interaction**: no prompts during normal operation.

LIT is **produced by LKE on the endpoint** and **consumed by apps, services, and infrastructure** to verify identity at the moment of use.

## Quick Start

> **Coming soon:** reference client/server and verification SDKs.

1. Read the **LIT Spec Overview**: SPEC/LIT-Spec-Overview.md
2. Explore the **Message Formats**: SPEC/LIT-Message-Formats.md
3. Understand **Trust States** and **Transitions**: SPEC/LIT-Trust-States.md
4. Review **Attestation Semantics** for Live Key: SPEC/LIT-Attestation-Semantics.md
5. Check **Security Considerations**: SPEC/LIT-Security-Considerations.md
6. Look at **Interop and Transport** options: SPEC/LIT-Interop-and-Transport.md

## Contributing

We welcome contributions to the **specification**, **examples**, **SDKs**, and **documentation**. Please see:
- CONTRIBUTING.md
- CODE_OF_CONDUCT.md
- GOVERNANCE.md

## Security

If you believe you’ve found a security issue related to the specification or reference code in this repository, please follow the process in:
- SECURITY.md

For product vulnerabilities (LKE, Enterprise LIT Server, Secure Internet Gateway), use WinMagic’s responsible disclosure channel as described in `SECURITY.md`.

---

