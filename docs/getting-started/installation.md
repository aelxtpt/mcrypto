---
title: Installation
---

# Installation

## Supported systems

The checked-in Pixi workspace supports:

- Linux x86_64 (`linux-64`)
- Linux AArch64 (`linux-aarch64`)
- macOS arm64 (`osx-arm64`)
- Mojo `1.0.0`
- MAX Core `26.5.0`

Windows and Intel macOS are not workspace targets.

## Install Pixi

Install Pixi using its maintained installer, then open a new shell if the installer updates `PATH`:

```sh
curl -fsSL https://pixi.sh/install.sh | sh
pixi --version
```

## Obtain all sources

The canonical source is `https://github.com/aelxtpt/mcrypto.git`:

```sh
git clone https://github.com/aelxtpt/mcrypto.git
cd mcrypto
pixi install
```

`pixi install` resolves the exact Mojo and MAX Core versions pinned by `pixi.toml`. Use `pixi install -e docs` for documentation work.

## Run a consumer file

mcrypto is a source-layout library. Point `-I` at its absolute `src` directory:

```sh
pixi run mojo run -I /absolute/path/to/mcrypto/src app.mojo
```

For another project, vendor mcrypto or add it as a Git submodule, then pass that checkout's `src` path to every Mojo build or run command.

Tagged source checkouts and GitHub-generated source archives contain the complete library.

> **Important:**
> mcrypto currently has no PyPI, Conda, or Modular registry package and no `.mojopkg` installer. `pip install mcrypto`, `conda install mcrypto`, and package-name-only Mojo imports are not supported installation paths.

Continue with the [quick start](quickstart.md).