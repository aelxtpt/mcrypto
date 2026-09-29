# mcrypto

mcrypto is a source-layout Mojo library of cryptographic primitives, compatibility algorithms, and batched implementations. Version `0.1.0` pins Mojo `1.0.0` with MAX Core `26.5.0` on Linux x86_64, Linux AArch64, and macOS arm64.

> **Disclaimer:** This library was written with the assistance of AI and may contain errors.

## Source-checkout quick start

mcrypto is not published to PyPI, Conda, the Modular package registry, or as a `.mojopkg`. Use a source checkout:

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

Consumers point Mojo at this checkout's `src` directory:

```sh
pixi run mojo run -I /absolute/path/to/mcrypto/src app.mojo
```

Tagged source checkouts and GitHub-generated source archives contain the complete library. Runtime consumers import from the checkout's `src` directory.

## Documentation and coverage

- [Documentation source](docs/index.md)
- [Installation](docs/getting-started/installation.md)
- [Algorithm guides](docs/algorithms/index.md)
- [Exact algorithm inventory](docs/reference/algorithms.md)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)
- [MIT license](LICENSE)

The committed coverage registry closes every maintained catalog group over embedded known-answer, negative, state, timing, and path evidence. The native workflow runs the behavioral suite on Linux x86_64 and AArch64.
