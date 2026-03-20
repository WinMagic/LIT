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
# Repository content: LIT Reference Project (Windows)

This reference project demonstrates **LIT** concepts in action on **Windows 10/11** and **Windows Server 2016+**.

For hands‑on evaluation, a hosted **LIT test server** is available:

- **Server:** https://lit.winmagic.dev  
- **Purpose:** experiment with client components **without** deploying your own server.

---

## Client Components

- **LiveKeyEngine (Windows Service)**  
  - Creates and registers a user’s **LiveKey** for passwordless access to the sample **“User Tasks”** service hosted by the LIT server.  
  - Enforces **LiveKey usage policy** (allows or denies LiveKey access based on policy).

- **WinMagic CNG Key Storage Provider (KSP)**  
  - Creates, stores, and manages **TPM‑backed LiveKeys** via the Windows CNG infrastructure.

---

## Test Server Endpoints

The LIT test server exposes a REST API used by the client for:

- **LiveKey registration**  
- **User certificate retrieval**  
- **CA certificate retrieval**

> You can reconfigure the client to point at your own server later; defaults target the public test server to minimize setup.

---

## LiveKeyEngine Configuration

**Registry path:**  
`HKLM\SYSTEM\CurrentControlSet\Services\LiveKeyEngine\Parameters`

Supported values:

---
Name      : Host
Type      : REG_SZ
Default   : lit.winmagic.dev
Purpose   : LIT server hostname

Name      : Port
Type      : REG_DWORD
Default   : 443
Purpose   : LIT server TCP port (HTTPS)

Name      : LogFile
Type      : REG_SZ
Default   : C:\Windows\Temp\LiveKeyEngine.log
Purpose   : Absolute path to the service log file

Name      : LogLevel
Type      : REG_DWORD
Default   : 2   (LOG_LEVEL_INFO)
Purpose   : Logging verbosity (e.g., 1=ERROR, 2=INFO, 3=DEBUG)
---

## Quick Build & Run (Example)

1. **Prereqs**
   Client:
   - Microsoft Windows 10/11 with TPM 2.0 enabled
   - Microsoft Visual Studio (Tested with version 2022)   
   Server:
   - MS Server with IIS

2. **Build**
   - Open the solution in Visual Studio 
   - Build **Release x64**

3. **Install the Live Key Engine (Service)**
   - Open an elevated Developer Command Prompt  
   - `sc.exe create LiveKeyEngine binPath= "C:\path\to\LiveKeyEngine.exe" start= auto`
   - `sc.exe start LiveKeyEngine`

4. **Install and Register WinMagic CNG Key Storage Provider**
   - Copy WmKsp.dll to \Windows\System32 directoy
   - Launch Windows Command Prompt as Administrator
   - `rundll32 "C:\Windows\System32\WmKsp.dll" Register`

5. **Run the Server**
   - Launch the demo server (listens for mTLS)  
   - Verify it trusts the issuing CA used by Live Key Engine

6. **Run the Client**
   - The client uses the TPM‑bound key + mTLS to login to server
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
