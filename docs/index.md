---
title: Home
---

# mcrypto

mcrypto `0.1.0` is a cryptography library for Mojo `1.0.0`. It provides fixed hashes and XOFs, symmetric and public-key primitives, KDFs, secure-memory helpers, compatibility algorithms, and prepared/batched paths.

> **Disclaimer:** This library was written with the assistance of AI and may contain errors.

## Choose a task

- **Install mcrypto:** [Getting started](getting-started/index.md)
- **Choose and call a primitive:** [Algorithm guides](algorithms/index.md)
- **Find an exact catalog name or spelling:** [Algorithm inventory](reference/algorithms.md)

## Supported workflow

mcrypto is published on the [modular-community](https://repo.prefix.dev/modular-community) conda channel:

```sh
pixi add mcrypto
```

Import by package name; the installed precompiled library is discovered without an `-I` path. Working from a source checkout instead passes `-I src` to every Mojo command.

Each guide embeds a complete runnable example; the same sources are also published as standalone `.mojo` files in `docs/examples/`.
