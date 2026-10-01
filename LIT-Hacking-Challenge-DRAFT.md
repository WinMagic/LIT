## LIT Hacking Challenge

### Our Security Claim

We claim that the direct connection between a LIT client and the LIT test server is protected against Man-in-the-Middle (MitM) attacks.

The LIT test server uses mutual TLS (mTLS) to authenticate the client at the transport layer. The client must prove possession of the private key associated with its registered LiveKey. The private key is not transmitted to the server and is not intended to be exportable from the protected client environment.

We invite security researchers, ethical hackers, students, and other security enthusiasts to challenge this claim.

### The Target

The **LIT test server is a synthetic Service Provider** created specifically for demonstration and authorized security testing. It exposes a synthetic **User Tasks** service through a direct mTLS-protected connection.

Each test user has an independent task list containing synthetic test data only. The service does not contain production data, customer information, or confidential business information.

The challenge environment is hosted on an Amazon EC2 instance owned and operated by WinMagic specifically for this challenge. AWS infrastructure and AWS-managed services are not part of the challenge scope. Testing is limited to the LIT Service Provider and associated challenge assets. 

The objective of the challenge is to determine whether an attacker can defeat the mTLS protection and modify another test user's task list without possessing or legitimately using that user's LiveKey private key.

Client registration is performed through a separate, unprotected REST API that is intentionally provided to simplify challenge setup and onboarding. Participants may use this API to register their own test clients and keys. The registration process itself is not considered a security boundary and is not part of the challenge scope. The objective of the challenge begins after a client's public key has been successfully registered with the Service Provider.

### What Counts as a Successful Attack?

A successful attack must demonstrate that an attacker can:

1. Intercept, relay, redirect, or otherwise manipulate the connection between a legitimate LIT client and the LIT test server.
2. Use the attack to modify another test user's task list without possessing or legitimately using that user's LiveKey private key.

The result must be reproducible and must demonstrate that the protection was bypassed through the client-to-server connection.

Finding a user-interface issue, modifying your own task list, or obtaining access by changing the server or victim-client configuration does not, by itself, constitute a successful attack.

### Challenge Scope and Assumptions

The objective of this challenge is to evaluate the security of the direct mTLS-protected connection between the LIT client and the synthetic LIT Service Provider.

The challenge assumes that the attacker has access to the network and can observe, intercept, relay, redirect, replay, or otherwise manipulate traffic between the client and server. The attacker may operate as a Man-in-the-Middle (MitM) or Adversary-in-the-Middle (AiTM).

The challenge does not assume that the attacker has physical access to the client device or administrative control over it. The client device, operating system, and LIT client software are assumed to remain trusted and uncompromised throughout the attack.

A valid attack must therefore succeed without:

* Physical access to the client device
* Installing software, malware, agents, browser extensions, hooks, proxies, debuggers, monitoring tools, or any other software on the client device
* Modifying the LIT client software
* Modifying the operating system or its configuration
* Taking control of the user's session

The following activities are within the scope of the challenge:

* Man-in-the-Middle and Adversary-in-the-Middle attacks
* TLS interception or relay
* Client-certificate substitution or misuse
* Attempts to authenticate without possession of the registered private key
* Attempts to redirect a legitimate LIT client to an attacker-controlled service
* Attempts to modify another test user's task list by bypassing the mTLS protection

The following activities are outside the scope of the challenge:

* Attacks against AWS infrastructure or AWS-managed services
* Attacks against production systems or unrelated infrastructure
* Physical attacks against devices
* Destructive testing
* Installation of malware, agents, browser extensions, hooking libraries, proxies, debuggers, or other attack software on a participant's device
* Modification of the client device, operating system, or LIT client software
* Unauthorized access to, modification of, or deletion of another participant's environment

A successful challenge submission must demonstrate that the attacker can defeat the intended mTLS protection and modify another user's synthetic task list while operating solely from the network and without compromising, controlling, or modifying the legitimate client device.

Researchers who wish to evaluate attacks involving device compromise, malware, physical access, key extraction, operating system modifications, reverse engineering, or client-side instrumentation are welcome to do so separately. However, such attacks are outside the scope of this challenge and will not be considered successful challenge submissions.

### AWS Hosting and Acceptable Testing

The challenge environment is hosted on Amazon Web Services (AWS). Participants are authorized to perform security testing only against the challenge assets explicitly provided by WinMagic.

Participants must not attempt to test, attack, disrupt, or assess:

* AWS infrastructure
* AWS-managed services
* AWS networks
* Systems belonging to other AWS customers
* Any assets not explicitly identified as part of this challenge

This challenge is intended to evaluate the security of the LIT application and its mTLS-based authentication model, not the security of AWS. AWS permits penetration testing of customer-owned EC2 instances, but does not permit testing of AWS infrastructure or services themselves. 

The following activities are prohibited:

* Denial-of-Service (DoS) attacks
* Distributed Denial-of-Service (DDoS) attacks
* Simulated DoS or DDoS attacks
* Request flooding
* Protocol flooding
* Port flooding
* Load, stress, or volumetric testing
* Any activity intended to degrade the availability, performance, or stability of the challenge environment

AWS identifies DoS, DDoS, request flooding, protocol flooding, and similar activities as prohibited penetration testing activities. 

Participants must conduct their testing in a responsible manner and immediately stop any activity that could negatively impact service availability.

Any vulnerability discovered in AWS services themselves is outside the scope of this challenge and should be reported directly to AWS through the AWS security reporting process. 

### Prebuilt Binaries for Windows client

To help participants start testing immediately, we provide prebuilt LIT client binaries.

Using these binaries eliminates the need to compile the LIT source code or configure a local build environment before beginning the challenge. Participants can download the supplied package, complete the required setup, and connect to the synthetic LIT Service Provider.

This challenge is intended as a lightweight version of the broader SP1/SP2 scenarios \[TODO: add the link]. Participants can begin evaluating the mTLS protection without downloading, installing, and configuring the full SD/ME client environment.

The prebuilt binaries are built from the source code available in this repository. Researchers who wish to go deeper may still build the project from source, modify the client, evaluate the complete environment, and perform broader security analysis.

### Installation and configuration on a Windows client:

* **Prebuilt binaries:** [https://github.com/WinMagic/LIT/tree/main/Windows/client/binaries/x64]

SHA256 hash of LiveKeyEngine.exe:
22629d0802502bc05e0d0b86af8cd6ecae78db851fe7da446d27fc5634f8af1e

SHA256 hash of WmKsp.dll:
6204f761c4fa2d65aa4412e7cd36a609f8a6970b7e68450393aa31e6a59ea939



**Install the Live Key Engine (Service)**

Copy LiveKeyEngine.exe to C:\\Windows\\System32 directoy  
Launch Windows Command Prompt as Administrator  
Execute

sc.exe create LiveKeyEngine binPath="C:\\Windows\\System32\\LiveKeyEngine.exe" start= auto  
sc.exe start LiveKeyEngine

**Install and Register WinMagic CNG Key Storage Provider**

Copy WmKsp.dll to C:\\Windows\\System32 directoy  
In the Administrator's command prompt  
Execute

rundll32 "C:\\Windows\\System32\\WmKsp.dll" Register



Participants should verify the published SHA-256 checksum before running the downloaded binaries.

Where available, participants should also verify the digital signature of the release package.

### Reporting a Finding

A valid report should include:

* A clear description of the attack
* The affected test account or task list
* The date and approximate time of the test
* Complete reproduction steps
* Relevant logs, network captures, screenshots, or other supporting evidence
* An explanation of how the attack bypassed the expected mTLS protection

Please report potential vulnerabilities privately to:

**research@winmagic.com**

Do not publicly disclose a suspected vulnerability until WinMagic has had a reasonable opportunity to investigate and respond.

### A Challenge, Not a Promise

Security claims should be tested, not merely asserted.

This challenge is an invitation to independently examine the LIT design and reference implementation, identify weaknesses, and help improve the security of machine-native authentication.

