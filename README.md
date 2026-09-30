# mcrypto

mcrypto is a Mojo library of cryptographic primitives, compatibility algorithms, and batched implementations. Version `0.1.0` targets Mojo `1.0.0` on Linux x86_64, Linux AArch64, and macOS arm64.

> **Disclaimer:** This library was written with the assistance of AI and may contain errors.

## Install

mcrypto is published on the [modular-community](https://repo.prefix.dev/modular-community) conda channel. Add the channel to your Pixi workspace and install the package:

```toml
[workspace]
channels = [
  "https://conda.modular.com/max",
  "https://repo.prefix.dev/modular-community",
  "conda-forge",
]
```

```sh
pixi add mcrypto
```

Then import by package name. The precompiled library is discovered automatically, so no `-I` path is needed:

```mojo
from mcrypto.hashes import HashAlgorithm, hash


def main() raises:
    print(hash(HashAlgorithm.SHA256, "abc".as_bytes()))
```

## Work from a source checkout

Contributing and local development run against a checkout:

```sh
git clone https://github.com/aelxtpt/mcrypto.git
cd mcrypto
pixi install
pixi run mojo run -O1 -I src docs/examples/quickstart_hash.mojo
```

Expected output:

```text
quickstart-hash: ok
```

To consume a checkout instead of the published package, point `-I` at its absolute `src` directory:

```sh
pixi run mojo run -I /absolute/path/to/mcrypto/src app.mojo
```

## Documentation and coverage

- [Documentation source](docs/index.md)
- [Installation](docs/getting-started/installation.md)
- [Algorithm guides](docs/algorithms/index.md)
- [Exact algorithm inventory](docs/reference/algorithms.md)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)
- [MIT license](LICENSE)

The committed coverage registry closes every maintained catalog group over embedded known-answer, negative, state, timing, and path evidence. The native workflow runs the behavioral suite on Linux x86_64 and AArch64.
