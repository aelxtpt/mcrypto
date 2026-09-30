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

In a workspace that installed the published package, run that program with no import path flag:

```sh
pixi add mcrypto
pixi run mojo run app.mojo
```

Expected stdout is exactly:

```text
quickstart-hash: ok
```

From an mcrypto checkout, the same source runs against the checked-in `src` directory:

```sh
pixi run mojo run -O1 -I src docs/examples/quickstart_hash.mojo
```

Every algorithm is imported from its own documented module. The root `mcrypto` module only marks the package directory and re-exports nothing. Next, read [bytes and errors](bytes-errors.md).
