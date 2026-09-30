---
title: Getting started
---

# Getting started

Install mcrypto as a conda package on Linux x86_64, Linux AArch64, or macOS arm64.

1. [Install the toolchain and the package](installation.md).
2. [Run the executable hash example](quickstart.md).
3. [Understand bytes, ownership, and failures](bytes-errors.md).

> **Note:**
> The published package depends on `mojo-compiler >=1.0.0,<1.1.0` and installs it for you, so use the compiler it provides. Inside an mcrypto checkout, run `pixi install` rather than mixing an unrelated system Mojo into these commands.