# LIT — Live Identity in Transaction

**By WinMagic — creators of the Live Key Engine (LKE) and the Secure Internet**

LIT is an **open specification** for a **continuous, cryptographic identity signal** delivered at the **transaction level**, with **zero user interaction**.

- **LIT (Live Identity in Transaction):** An identity signal bound to a verified human and a verified endpoint, emitted continuously for each transaction.
- **Live Key Engine (LKE):** WinMagic’s endpoint component that generates and governs the **Live Key**, evaluates conditions (user presence, environment, policy), and **emits LIT**. *LKE is proprietary; the LIT spec and public Live Key semantics are open.*

This repository contains:
- **Specifications** for LIT
- **Public semantics** for Live Key (definition and attestation format)
- **Reference client/server examples** (minimal, for learning)
- **Developer SDK stubs** (JS, Python, Go)

> **Goal:** Enable an Internet where each transaction carries **verifiable, policy‑bound identity**—without prompts, passwords, or fragile tokens.

---

## Why LIT?

Authentication today is dominated by **logins**, **tokens**, and **cookies**—mechanisms not designed for continuous, transaction-level identity. Attackers exploit this gap (token theft, AiTM, session hijack).

**LIT changes the posture**:
- **Continuous**: identity is asserted across the session, not just at login.
- **Bound**: to a verified person and a verified endpoint.
- **Policy-governed**: available only when defined conditions are met.
- **Zero user interaction**: no prompts during normal operation.

LIT is **produced by LKE on the endpoint** and **consumed by apps, services, and infrastructure** to verify identity at the moment of use.

---

## What’s Open vs. Proprietary

**Open here (this repo):**
- LIT specification (message types, state machine, trust transitions)
- Live Key public semantics (definition, properties, attestation schema)
- Reference client/server examples (minimal)
- SDK stubs for verification

**Proprietary (WinMagic products):**
- **LKE — Live Key Engine (Endpoint):** Produces and governs Live Key; emits LIT.
- **Enterprise LIT Server:** Policy engine, validation, risk, admin console.
- **Secure Internet Gateway:** Certificate-less mTLS and identity-assured routing.

---

## Quick Start

> **Coming soon:** reference client/server and verification SDKs.

1. Read the **LIT Spec Overview**: SPEC/LIT-Spec-Overview.md
2. Explore the **Message Formats**: SPEC/LIT-Message-Formats.md
3. Understand **Trust States** and **Transitions**: SPEC/LIT-Trust-States.md
4. Review **Attestation Semantics** for Live Key: SPEC/LIT-Attestation-Semantics.md
5. Check **Security Considerations**: SPEC/LIT-Security-Considerations.md
6. Look at **Interop and Transport** options: SPEC/LIT-Interop-and-Transport.md

---

## Contributing

We welcome contributions to the **specification**, **examples**, **SDKs**, and **documentation**. Please see:
- CONTRIBUTING.md
- CODE_OF_CONDUCT.md
- GOVERNANCE.md

---

## Security

If you believe you’ve found a security issue related to the specification or reference code in this repository, please follow the process in:
- SECURITY.md

For product vulnerabilities (LKE, Enterprise LIT Server, Secure Internet Gateway), use WinMagic’s responsible disclosure channel as described in `SECURITY.md`.

---

## License

We recommend **Apache 2.0** for this repository. (See `LICENSE`.)

---

## Announcement

Read the public announcement below (also usable as a blog or PR intro).

### Introducing the LIT Open Specification Project

A new identity signal for every transaction. **LIT** is an open specification that enables **verifiable, continuous identity** without user interaction, bound to real people and real endpoints.

This repo includes the LIT spec, Live Key public semantics, reference examples, and SDK stubs. The production-grade engines—**LKE (endpoint)**, **Enterprise LIT Server**, and **Secure Internet Gateway**—remain WinMagic products.

**Get involved:** Explore the spec, try the examples (as they land), and contribute feedback or implementations via issues and pull requests.

> **LIT enables Live Identity in every transaction. Let’s build the future together.**

---
