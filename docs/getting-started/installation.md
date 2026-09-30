---
title: Installation
---

# Installation

## Supported systems

The published package and the checked-in Pixi workspace both target:

- Linux x86_64 (`linux-64`)
- Linux AArch64 (`linux-aarch64`)
- macOS arm64 (`osx-arm64`)
- Mojo `1.0.0`

Windows and Intel macOS are not targets.

## Install Pixi

Install Pixi using its maintained installer, then open a new shell if the installer updates `PATH`:

```sh
curl -fsSL https://pixi.sh/install.sh | sh
pixi --version
```

## Install the package

mcrypto is published on the [modular-community](https://repo.prefix.dev/modular-community) conda channel. Add the channel to your workspace manifest:

```toml
[workspace]
channels = [
  "https://conda.modular.com/max",
  "https://repo.prefix.dev/modular-community",
  "conda-forge",
]
```

Then install it:

```sh
pixi add mcrypto
```

This installs the precompiled `mcrypto.mojoc` together with the `mojo-compiler` it depends on. The package constrains that compiler to `>=1.0.0,<1.1.0`, because a precompiled Mojo library only loads under the compiler version that produced it.

No source checkout and no `-I` path are required:

```mojo
from mcrypto.hashes import HashAlgorithm, hash
```

## Work from a source checkout

The canonical source is `https://github.com/aelxtpt/mcrypto.git`:

```sh
git clone https://github.com/aelxtpt/mcrypto.git
cd mcrypto
pixi install
```

`pixi install` resolves the exact Mojo and MAX Core versions pinned by `pixi.toml`.

To consume a checkout instead of the published package, vendor mcrypto or add it as a Git submodule, then pass that checkout's `src` directory to every Mojo build or run command:

```sh
pixi run mojo run -I /absolute/path/to/mcrypto/src app.mojo
```

Continue with the [quick start](quickstart.md).
