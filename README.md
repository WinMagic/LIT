# Live Identity in Transaction (LIT)
### The General Architecture for Continuous, Machine‑Native Identity

# Deterministic Identity in Transaction (DIT)  
### The mTLS‑Based Identity Pulse That Makes LIT Real

---

## Stop Blaming the User. Start Engineering the Machine.

For decades, cybersecurity has failed because the industry treats identity as a **Human‑to‑Human** problem instead of a **Machine‑to‑Machine** one. Users should never have to detect phishing, interpret ambiguous UI cues, or manage authentication flows. That is a failure of architecture—not a failure of human behavior.

**LIT and DIT correct the architecture.**  
LIT provides the **framework**; DIT provides the **mechanism**.

---

## What Is LIT? (Live Identity in Transaction) — The General Solution

**LIT is the principle that digital identity must be:**

- **Continuous** – proven at every step, not only at login  
- **Machine‑native** – bound to hardware, not to UI flows  
- **Transport‑layer enforced** – cryptographically, not visually  
- **Unspoofable** – constructed so phishing/hijacking is impossible  
- **Sessionless** – not based on bearer tokens or cookies

Under LIT, a “login” becomes obsolete because identity is **always alive**, always verified, and always cryptographically bound to the endpoint’s state.

---

## What Is DIT? (Deterministic Identity in Transaction) — The Practical Handshake

DIT is the applied implementation of LIT using:

- **mTLS (mutual TLS)**
- **Hardware‑anchored private keys**
- A continuous **Identity Pulse** (cryptographic heartbeat)
- Deterministic handshake logic at the **transport layer**

DIT moves identity from the user interface to the network layer—where machines actually communicate—and eliminates phishing, session hijacking, token replay, cookie theft, MFA fatigue, and other UI‑driven social‑engineering attacks.

---

## Why LIT & DIT?

### 1) The Endpoint *Is* the Room
There is no “building” to secure on the internet. Identity must be anchored to the device itself—turning it into a **Portable Sanctuary** projected across the open internet through mTLS.

### 2) Identity as a Timeline, Not a Snapshot
Login is a snapshot. Attackers exploit the time *after* login.  
LIT/DIT introduce **timeline identity**, continuously proving device (+ user) presence across the entire session.

### 3) Simplicity *Is* Security
We don’t need more scaffolding (e.g., complex token wrappers). We already have the right primitive: **mTLS**.  
LIT/DIT remove friction by fixing the foundation.

---

## Official Standards Submission

On **March 2, 2026**, we submitted both **LIT (Live Identity in Transaction)** and **DIT (Deterministic Identity in Transaction)** proposals to the IETF and W3C for standardization.

We open‑sourced the handshake because clarity is a public good—and secure architecture should be available to all. When the architecture is correct, security becomes a background rhythm and humans are finally unburdened.

---

## Repository Contents

This repository contains a **fully working reference project** with **client and server** components that demonstrate LIT/DIT in action:

- **Live Key Engine service — reference project**  
  A Windows service anchoring cryptographic identity in hardware (TPM/CNG), running the DIT Identity Pulse, and providing continuous endpoint identity.

- **TPM‑backed mTLS authentication**  
  Client keys are generated inside the TPM (non‑exportable, hardware‑bound) and used for **client‑auth mTLS**.

- **Microsoft CNG Key Storage Provider**  
  Integration with NCrypt/CNG providers (including TPM KSP), keeping keys managed within the secure Windows platform.

- **Issuing X.509 client certs without CSRs**  
  A streamlined flow that issues client certificates **without** CSR exchanges—by validating the device’s public key directly—dramatically reducing PKI friction.

- **Authenticate & admit users via mTLS presence**  
  The server authenticates based on the presence of the correct mTLS identity—no passwords, no UI prompts—identity is a property of the connection.

---

## Get Started

- **Read the Manifesto:**  
  _[Add link to Op‑Ed / Whitepaper]_

- **Review the Standards Drafts:**  
  _[Add link to IETF submission]_  
  _[Add link to W3C submission]_

- **Explore the Code:**  
  _[Add link to DIT reference implementation]_  
  _[Add link to the Live Key Engine service]_  
  _[Add link to client/server demo]_

---

## Quick Build & Run (Example)

> Adjust these steps to your environment. The reference solution targets Windows (TPM + CNG) for the endpoint service and mTLS demo.

1. **Prereqs**
   - Windows 10/11 or Windows Server with TPM 2.0 enabled  
   - Visual Studio (x64) + Windows SDK  
   - OpenSSL (optional, for test tooling)  

2. **Build**
   - Open the solution in Visual Studio  
   - Build **Release x64**

3. **Install the Live Key Engine (Service)**
   - Open an elevated Developer Command Prompt  
   - `sc.exe create LiveKeyEngine binPath= "C:\path\to\LiveKeyEngine.exe" start= auto`  
   - `sc.exe start LiveKeyEngine`

4. **Run the Server**
   - Launch the demo server (listens for mTLS)  
   - Verify it trusts the issuing CA used by Live Key Engine

5. **Run the Client**
   - The client uses the TPM‑bound key + mTLS to connect  
   - Observe successful authentication based on Identity Pulse

---

## Architecture (High‑Level)

- **LIT (architecture)**: defines that identity lives at the transport layer, is continuous, and is machine‑anchored.  
- **DIT (implementation)**: uses mTLS + hardware keys to create a **continuous Identity Pulse**.  
- **Live Key Engine (service)**: provisions/anchors keys, manages identity lifecycle, and participates in the DIT handshake.  
- **Server**: admits sessions based on mTLS identity (no UI auth), maintaining continuous proof throughout the session.

---

## Vision

> “If you can help with relatively little effort and the impact is meaningful, then giving isn't a loss. It makes the world better for everyone.”  
> — **Thi Nguyen‑Huu, Founder of WinMagic**

LIT/DIT redefine identity as something machines handle **correctly and continuously**—not something humans struggle to manage. The human should not be the weakest link. The architecture should be the strongest.

---

## Contributing

We welcome issues, discussions, and PRs.  
If you want to participate in standards work around LIT/DIT, please open a discussion topic—identity should be open, global, and collaboratively engineered.

---

## License

MIT