---
title: Quick start
---

# Quick start

The smallest supported path imports the hash dispatcher explicitly, hashes an owned byte list through a borrowed `Span`, and checks the result.

<a id="example-quickstart-hash"></a>
## Executable example

```mojo
from std.testing import assert_equal
from mcrypto.hashes import HashAlgorithm, hash
from mcrypto.encoding.algorithm import EncodingTransform
from mcrypto.encoding.transforms import transform


def main() raises:
    var digest = hash(HashAlgorithm.SHA256, "abc".as_bytes())
    var expected = transform(
        EncodingTransform.HEX_DECODE,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        .as_bytes(),
    )
    assert_equal(digest, expected)
    print("quickstart-hash: ok")
```

Run the exact included file from the repository root:

```sh
pixi run mojo run -O1 -I src docs/examples/quickstart_hash.mojo
```

Expected stdout is exactly:

```text
quickstart-hash: ok
```

In a consumer repository, replace `src` with mcrypto's absolute source path:

```sh
pixi run mojo run -I /absolute/path/to/mcrypto/src app.mojo
```

The root `mcrypto` module re-exports only `initialize`, core traits and constant-time equality, plus SHA-224/256/384/512 types and helpers. Import other algorithms from their documented modules. Next, read [bytes and errors](bytes-errors.md).