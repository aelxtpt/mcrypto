# Security Policy

## Scope

mcrypto is a low-level cryptographic library. It provides primitives, dispatchers, state machines, and memory helpers. It does not design a protocol, authenticate peer identities, manage long-term keys, rotate credentials, or make a compromised host trustworthy.

**In scope** for a security report:

- A maintained algorithm producing output that disagrees with its specification or known-answer vectors.
- Authentication accepted for a forged tag, ciphertext, MAC, or signature.
- A secret-dependent branch, table lookup, or memory access in a path documented as constant-time.
- An out-of-bounds access or missing length validation reachable from a documented public API.
- A helper that fails to wipe or page-lock memory it claims to wipe or lock.
- Entropy that is predictable, reused, or silently substituted after an operating-system entropy failure.

**Out of scope**:

- Using a documented compatibility algorithm (RC4, DES variants, RC2, MD2, MD4, MD5, SHA-1, and similar) in a new protocol.
- Misuse already described in the algorithm guides, such as reusing a nonce under one key.
- Weaknesses in a caller's protocol, key management, or deployment.
- Issues that require an already-compromised process or host.

## Supported versions

| Version | Supported |
|:--|:--|
| `0.1.x` | Yes |

Only the latest release published on the [`modular-community`](https://repo.prefix.dev/modular-community) channel receives fixes.

## Reporting a vulnerability

Do not open a public issue or pull request. Use GitHub's [private vulnerability reporting](https://github.com/aelxtpt/mcrypto/security/advisories/new) to create a draft security advisory, which stays private until a fix is available.

Include, as far as it applies:

- The affected algorithm, module, and released version.
- A minimal reproducer, ideally a single `.mojo` file.
- The expected result, the observed result, and why the difference is a security problem.
- The target, compiler version, and optimization settings, since some code paths are target-gated.

## What to expect

- An acknowledgement that the report was received.
- An assessment of whether it is in scope and how it will be prioritized.
- Credit in the advisory, unless you ask to stay anonymous.

There is no bug bounty.

## A note on the implementation

This library was written with the assistance of AI and may contain errors. Its tests establish agreement for the exercised inputs on the exercised targets; they are not a proof of memory safety, side-channel resistance, or protocol suitability. Reports are welcome precisely because that evidence is incomplete.
