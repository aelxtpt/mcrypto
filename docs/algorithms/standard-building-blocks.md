---
title: Standard building blocks
---

# Standard building blocks

These APIs implement independent standards and accept application-selected inputs.
They do not implement a handshake, message envelope, or peer authentication.
The executable example is `docs/examples/standard_building_blocks.mojo`.

## HKDF extraction and expansion

`mcrypto.kdf.hkdf` implements [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869).

- `extract(hash_algorithm, salt, input_key_material)` returns a HashLen-byte PRK.
- `expand(hash_algorithm, pseudorandom_key, context, output_bytes)` accepts a PRK
  of at least HashLen bytes and a length in `0..255*HashLen`.
- SHA-256 and SHA-512 are supported. Empty salt means HashLen zero bytes; empty
  input material and context are valid. Expansion uses the standard counter 1.
- `derive(hash_algorithm, salt, key, context, output_bytes)` composes the stages
  and retains its existing positive-output-length requirement.

All byte inputs are borrowed spans and outputs are owned byte lists. The caller
owns and must protect returned PRKs. `derive` clears its temporary PRK.
Do not call `derive` when only expansion of an existing PRK is intended.

## PKCS#7

`mcrypto.padding.pkcs7.pad(data, block_size)` and `unpad(data, block_size)` follow
[RFC 5652 section 6.3](https://www.rfc-editor.org/rfc/rfc5652#section-6.3).
The block size is in bytes, from 1 to 255. An empty or aligned message receives a
complete padding block. Both functions return an owned list without changing the
input. AES-CBC remains a raw block-mode operation: apply padding explicitly.

Unpadding rejects empty/unaligned data, an invalid count, and inconsistent padding.
Every byte of the final block is scanned before the padding decision; content
failures use the same error. This is not authentication: authenticate before
exposing any decryption or padding failure to an untrusted peer. The fixed scan is
not a proof of constant-time machine code on every compiler or architecture.

## Unpadded Base64URL

`EncodingTransform.BASE64URL_NOPAD_ENCODE` and `BASE64URL_NOPAD_DECODE` implement
the URL-safe alphabet of [RFC 4648](https://www.rfc-editor.org/rfc/rfc4648) without
padding, as specified by [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515).
The parser names are `Base64URLNoPadEncode` and `Base64URLNoPadDecode`.

The decoder rejects `=`, whitespace, other alphabets, lengths congruent to one
modulo four, and nonzero unused trailing bits. Empty input is valid. Existing
padded selectors keep their original contracts. Encoding is not encryption.

## Bounded decompression

`inflate`, `zlib_decompress`, `gzip_decompress`, and the compression dispatcher
accept the keyword-only `max_output_bytes: Optional[Int] = None`.

- `None` preserves existing behavior; negative values raise; zero permits only
  an empty decoded output.
- A finite budget is checked before each literal append, stored-block copy, or
  back-reference expansion. Exceeding it raises without returning partial output.
- Concatenated Gzip members share one total budget. Checksums/framing are still
  validated; the limit does not turn a truncated stream into valid data.
- Supplying a budget to a compression selector raises instead of ignoring it.

The budget bounds decoded bytes, not total process memory or CPU time. Select it
at the application boundary. DEFLATE/Zlib/Gzip wire formats remain unchanged
([RFC 1951](https://www.rfc-editor.org/rfc/rfc1951),
[RFC 1950](https://www.rfc-editor.org/rfc/rfc1950),
[RFC 1952](https://www.rfc-editor.org/rfc/rfc1952)).

## ML-KEM-512

`mcrypto.kem.mlkem512` implements the ML-KEM-512 parameter set of
[FIPS 203](https://csrc.nist.gov/pubs/fips/203/final).

| Value | Bytes |
|---|---:|
| Encapsulation/public key | 800 |
| Expanded decapsulation/secret key | 1632 |
| Ciphertext | 768 |
| Shared secret | 32 |
| Key-generation seed `d || z` | 64 |
| Encapsulation randomness `m` | 32 |

`keypair()` returns `(public_key, secret_key)`; `encapsulate(public_key)` returns
`(ciphertext, shared_secret)`. Both obtain fresh OS entropy.
`seed_keypair(seed)` and `encapsulate_deterministic(public_key, seed)` expose the
standard deterministic operations for reproducible tests; never reuse test seeds
or substitute predictable inputs for normal entropy.
`decapsulate(ciphertext, secret_key)` returns the shared secret.
The dispatcher exposes `KemAlgorithm.ML_KEM_512`, parsed as `ML-KEM-512`.

Malformed lengths, noncanonical encapsulation keys, and inconsistent embedded
key hashes raise. Correct-length invalid ciphertexts instead produce the FIPS
203 implicit-rejection secret without exposing a validity flag. A KEM does not
itself authenticate the sender or encrypt an application message.

Ranks 2 and 3 share an internal compile-time-specialized core. ML-KEM-512 uses
eta1=3, eta2=2; ML-KEM-768 uses eta1=eta2=2. Both use du=10 and dv=4.
Existing ML-KEM-768 and X-Wing valid outputs and public interfaces are retained;
expanded decapsulation keys are checked against their embedded hash.

The NIST potential-updates spreadsheet was checked on 2026-10-11: its Appendix A
zeta-index clarification and Algorithm 15 comment correction do not change byte
formats or computed results. Known-answer fixtures record their NIST/ACVP source,
revision and full-byte expectations in `tests/fixtures/mlkem`. Tests are evidence
for their exercised inputs, not a certification or independent cryptographic audit.
