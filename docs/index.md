---
title: Home
---

# mcrypto

mcrypto `0.1.0` is a source-layout cryptography library for Mojo `>=1.0.0,<2` and MAX `26.5.0`. It provides fixed hashes and XOFs, symmetric and public-key primitives, KDFs, secure-memory helpers, compatibility algorithms, and prepared/batched paths.

> **Disclaimer:** This library was written with the assistance of AI and may contain errors.

## Choose a task

- **Set up a source checkout:** [Getting started](getting-started/index.md)
- **Choose and call a primitive:** [Algorithm guides](algorithms/index.md)
- **Find an exact catalog name or spelling:** [Algorithm inventory](reference/algorithms.md)

## Supported workflow

mcrypto currently runs from a source checkout. Consumer commands add the repository's `src` directory to Mojo's import path with `-I`; there is no published package or installer artifact.

```sh
pixi run mojo run -I /absolute/path/to/mcrypto/src app.mojo
```

Each guide embeds a complete runnable example; the same sources are also published as standalone `.mojo` files in `docs/examples/`.
