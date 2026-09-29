---
title: Algorithm inventory
---

# Algorithm inventory

This is the canonical public-facing catalog of mcrypto algorithms and operations.
Every row links to a hand-written explanation and a complete runnable example for that exact algorithm.

> **Important:** Available means a documented public path exists.

## AEAD

| Algorithm | Public API/import | Selector or operation | Individual use and example | Family guide | Availability | Note |
|:--|:--|:--|:--|:--|:--|:--|
| <a id="aead-gcm"></a>`GCM` | `mcrypto.aead.combined.encrypt`<br>`mcrypto.aead.combined.decrypt`<br>`mcrypto.aead.detached.encrypt`<br>`mcrypto.aead.detached.decrypt` | `GCM`<br>`AES-GCM` | [Use and example](../algorithms/by-name/aead.md#aead-gcm) | [Guide](../algorithms/by-name/aead.md) | `available` | — |
| <a id="aead-ccm"></a>`CCM` | `mcrypto.aead.combined.encrypt`<br>`mcrypto.aead.combined.decrypt`<br>`mcrypto.aead.detached.encrypt`<br>`mcrypto.aead.detached.decrypt` | `CCM`<br>`AES-CCM` | [Use and example](../algorithms/by-name/aead.md#aead-ccm) | [Guide](../algorithms/by-name/aead.md) | `available` | — |
| <a id="aead-eax"></a>`EAX` | `mcrypto.aead.combined.encrypt`<br>`mcrypto.aead.combined.decrypt`<br>`mcrypto.aead.detached.encrypt`<br>`mcrypto.aead.detached.decrypt` | `EAX`<br>`AES-EAX` | [Use and example](../algorithms/by-name/aead.md#aead-eax) | [Guide](../algorithms/by-name/aead.md) | `available` | — |
| <a id="aead-chacha20-poly1305-ietf"></a>`ChaCha20-Poly1305-IETF` | `mcrypto.aead.combined.encrypt`<br>`mcrypto.aead.combined.decrypt`<br>`mcrypto.aead.detached.encrypt`<br>`mcrypto.aead.detached.decrypt` | `ChaCha20Poly1305`<br>`ChaCha20-Poly1305-IETF` | [Use and example](../algorithms/by-name/aead.md#aead-chacha20-poly1305-ietf) | [Guide](../algorithms/by-name/aead.md) | `available` | — |
| <a id="aead-xchacha20-poly1305-ietf"></a>`XChaCha20-Poly1305-IETF` | `mcrypto.aead.combined.encrypt`<br>`mcrypto.aead.combined.decrypt`<br>`mcrypto.aead.detached.encrypt`<br>`mcrypto.aead.detached.decrypt` | `XChaCha20Poly1305`<br>`XChaCha20-Poly1305-IETF` | [Use and example](../algorithms/by-name/aead.md#aead-xchacha20-poly1305-ietf) | [Guide](../algorithms/by-name/aead.md) | `available` | — |
| <a id="aead-aegis-128l"></a>`AEGIS-128L` | `mcrypto.aead.combined.encrypt`<br>`mcrypto.aead.combined.decrypt`<br>`mcrypto.aead.detached.encrypt`<br>`mcrypto.aead.detached.decrypt` | `AEGIS-128L`<br>`AEGIS128L` | [Use and example](../algorithms/by-name/aead.md#aead-aegis-128l) | [Guide](../algorithms/by-name/aead.md) | `available` | — |
| <a id="aead-aegis-256"></a>`AEGIS-256` | `mcrypto.aead.combined.encrypt`<br>`mcrypto.aead.combined.decrypt`<br>`mcrypto.aead.detached.encrypt`<br>`mcrypto.aead.detached.decrypt` | `AEGIS-256`<br>`AEGIS256` | [Use and example](../algorithms/by-name/aead.md#aead-aegis-256) | [Guide](../algorithms/by-name/aead.md) | `available` | — |
| <a id="aead-aes-256-gcm"></a>`AES-256-GCM` | `mcrypto.aead.combined.encrypt`<br>`mcrypto.aead.combined.decrypt`<br>`mcrypto.aead.detached.encrypt`<br>`mcrypto.aead.detached.decrypt` | `AES-256-GCM` | [Use and example](../algorithms/by-name/aead.md#aead-aes-256-gcm) | [Guide](../algorithms/by-name/aead.md) | `available` | — |
| <a id="aead-chacha20-poly1305"></a>`ChaCha20-Poly1305` | `mcrypto.aead.combined.encrypt`<br>`mcrypto.aead.combined.decrypt`<br>`mcrypto.aead.detached.encrypt`<br>`mcrypto.aead.detached.decrypt` | `ChaCha20-Poly1305`<br>`ChaCha20/Poly1305` | [Use and example](../algorithms/by-name/aead.md#aead-chacha20-poly1305) | [Guide](../algorithms/by-name/aead.md) | `available` | — |

## Stream ciphers

| Algorithm | Public API/import | Selector or operation | Individual use and example | Family guide | Availability | Note |
|:--|:--|:--|:--|:--|:--|:--|
| <a id="stream-cipher-chacha8"></a>`ChaCha8` | `mcrypto.ciphers.stream.xor`<br>`mcrypto.ciphers.stream.xor_eight` | `ChaCha8` | [Use and example](../algorithms/by-name/stream-cipher.md#stream-cipher-chacha8) | [Guide](../algorithms/by-name/stream-cipher.md) | `available` | — |
| <a id="stream-cipher-chacha12"></a>`ChaCha12` | `mcrypto.ciphers.stream.xor`<br>`mcrypto.ciphers.stream.xor_eight` | `ChaCha12` | [Use and example](../algorithms/by-name/stream-cipher.md#stream-cipher-chacha12) | [Guide](../algorithms/by-name/stream-cipher.md) | `available` | — |
| <a id="stream-cipher-chacha20"></a>`ChaCha20` | `mcrypto.ciphers.stream.xor`<br>`mcrypto.ciphers.stream.xor_eight` | `ChaCha20` | [Use and example](../algorithms/by-name/stream-cipher.md#stream-cipher-chacha20) | [Guide](../algorithms/by-name/stream-cipher.md) | `available` | — |
| <a id="stream-cipher-xchacha20"></a>`XChaCha20` | `mcrypto.ciphers.stream.xor`<br>`mcrypto.ciphers.stream.xor_eight` | `XChaCha20` | [Use and example](../algorithms/by-name/stream-cipher.md#stream-cipher-xchacha20) | [Guide](../algorithms/by-name/stream-cipher.md) | `available` | — |
| <a id="stream-cipher-xchacha20-counter-1"></a>`XChaCha20 (counter 1)` | `mcrypto.ciphers.stream.xor`<br>`mcrypto.ciphers.stream.xor_eight` | `StreamCipherAlgorithm.XCHACHA20_COUNTER1` | [Use and example](../algorithms/by-name/stream-cipher.md#stream-cipher-xchacha20-counter-1) | [Guide](../algorithms/by-name/stream-cipher.md) | `available` | — |
| <a id="stream-cipher-panama"></a>`Panama` | `mcrypto.ciphers.stream.xor` | `Panama`<br>`Panama-BE` | [Use and example](../algorithms/by-name/stream-cipher.md#stream-cipher-panama) | [Guide](../algorithms/by-name/stream-cipher.md) | `available` | — |
| <a id="stream-cipher-salsa20"></a>`Salsa20` | `mcrypto.ciphers.stream.xor`<br>`mcrypto.ciphers.stream.xor_eight` | `Salsa20` | [Use and example](../algorithms/by-name/stream-cipher.md#stream-cipher-salsa20) | [Guide](../algorithms/by-name/stream-cipher.md) | `available` | — |
| <a id="stream-cipher-xsalsa20"></a>`XSalsa20` | `mcrypto.ciphers.stream.xor`<br>`mcrypto.ciphers.stream.xor_eight` | `XSalsa20` | [Use and example](../algorithms/by-name/stream-cipher.md#stream-cipher-xsalsa20) | [Guide](../algorithms/by-name/stream-cipher.md) | `available` | — |
| <a id="stream-cipher-sosemanuk"></a>`Sosemanuk` | `mcrypto.ciphers.stream.xor`<br>`mcrypto.ciphers.stream.xor_eight` | `Sosemanuk` | [Use and example](../algorithms/by-name/stream-cipher.md#stream-cipher-sosemanuk) | [Guide](../algorithms/by-name/stream-cipher.md) | `available` | — |
| <a id="stream-cipher-arc4"></a>`ARC4` | `mcrypto.ciphers.stream.xor` | `ARC4` | [Use and example](../algorithms/by-name/stream-cipher.md#stream-cipher-arc4) | [Guide](../algorithms/by-name/stream-cipher.md) | `available` | — |
| <a id="stream-cipher-seal"></a>`SEAL` | `mcrypto.ciphers.stream.xor` | `SEAL`<br>`SEAL-LE` | [Use and example](../algorithms/by-name/stream-cipher.md#stream-cipher-seal) | [Guide](../algorithms/by-name/stream-cipher.md) | `available` | — |
| <a id="stream-cipher-wake-ofb"></a>`WAKE-OFB` | `mcrypto.ciphers.stream.xor` | `WAKE-OFB` | [Use and example](../algorithms/by-name/stream-cipher.md#stream-cipher-wake-ofb) | [Guide](../algorithms/by-name/stream-cipher.md) | `available` | — |
| <a id="stream-cipher-rabbit"></a>`Rabbit` | `mcrypto.ciphers.stream.xor` | `Rabbit` | [Use and example](../algorithms/by-name/stream-cipher.md#stream-cipher-rabbit) | [Guide](../algorithms/by-name/stream-cipher.md) | `available` | — |
| <a id="stream-cipher-hc-128"></a>`HC-128` | `mcrypto.ciphers.stream.xor` | `HC-128` | [Use and example](../algorithms/by-name/stream-cipher.md#stream-cipher-hc-128) | [Guide](../algorithms/by-name/stream-cipher.md) | `available` | — |
| <a id="stream-cipher-hc-256"></a>`HC-256` | `mcrypto.ciphers.stream.xor` | `HC-256` | [Use and example](../algorithms/by-name/stream-cipher.md#stream-cipher-hc-256) | [Guide](../algorithms/by-name/stream-cipher.md) | `available` | — |
| <a id="stream-cipher-chacha20-ietf"></a>`ChaCha20-IETF` | `mcrypto.ciphers.stream.xor`<br>`mcrypto.ciphers.stream.xor_eight` | `ChaCha20-IETF`<br>`ChaCha20IETF` | [Use and example](../algorithms/by-name/stream-cipher.md#stream-cipher-chacha20-ietf) | [Guide](../algorithms/by-name/stream-cipher.md) | `available` | — |
| <a id="stream-cipher-salsa20-12"></a>`Salsa20-12` | `mcrypto.ciphers.stream.xor`<br>`mcrypto.ciphers.stream.xor_eight` | `Salsa20-12` | [Use and example](../algorithms/by-name/stream-cipher.md#stream-cipher-salsa20-12) | [Guide](../algorithms/by-name/stream-cipher.md) | `available` | — |
| <a id="stream-cipher-salsa20-8"></a>`Salsa20-8` | `mcrypto.ciphers.stream.xor`<br>`mcrypto.ciphers.stream.xor_eight` | `Salsa20-8` | [Use and example](../algorithms/by-name/stream-cipher.md#stream-cipher-salsa20-8) | [Guide](../algorithms/by-name/stream-cipher.md) | `available` | — |

## Block ciphers

| Algorithm | Public API/import | Selector or operation | Individual use and example | Family guide | Availability | Note |
|:--|:--|:--|:--|:--|:--|:--|
| <a id="block-cipher-aes"></a>`AES` | `mcrypto.ciphers.dispatch.process` | `AES/ECB`<br>`AES/CBC`<br>`AES/CBC-CTS`<br>`AES/CFB`<br>`AES/OFB`<br>`AES/CTR`<br>`AES/XTS` | [Use and example](../algorithms/by-name/block-cipher.md#block-cipher-aes) | [Guide](../algorithms/by-name/block-cipher.md) | `available` | — |
| <a id="block-cipher-rc2"></a>`RC2` | `mcrypto.ciphers.dispatch.process` | `RC2/ECB`<br>`RC2/CBC`<br>`RC2/CBC-CTS`<br>`RC2/CFB`<br>`RC2/OFB`<br>`RC2/CTR` | [Use and example](../algorithms/by-name/block-cipher.md#block-cipher-rc2) | [Guide](../algorithms/by-name/block-cipher.md) | `available` | — |
| <a id="block-cipher-rc5"></a>`RC5` | `mcrypto.ciphers.dispatch.process` | `RC5/ECB`<br>`RC5/CBC`<br>`RC5/CBC-CTS`<br>`RC5/CFB`<br>`RC5/OFB`<br>`RC5/CTR` | [Use and example](../algorithms/by-name/block-cipher.md#block-cipher-rc5) | [Guide](../algorithms/by-name/block-cipher.md) | `available` | — |
| <a id="block-cipher-rc6"></a>`RC6` | `mcrypto.ciphers.dispatch.process` | `RC6/ECB`<br>`RC6/CBC`<br>`RC6/CBC-CTS`<br>`RC6/CFB`<br>`RC6/OFB`<br>`RC6/CTR` | [Use and example](../algorithms/by-name/block-cipher.md#block-cipher-rc6) | [Guide](../algorithms/by-name/block-cipher.md) | `available` | — |
| <a id="block-cipher-mars"></a>`MARS` | `mcrypto.ciphers.dispatch.process` | `MARS/ECB`<br>`MARS/CBC`<br>`MARS/CBC-CTS`<br>`MARS/CFB`<br>`MARS/OFB`<br>`MARS/CTR` | [Use and example](../algorithms/by-name/block-cipher.md#block-cipher-mars) | [Guide](../algorithms/by-name/block-cipher.md) | `available` | — |
| <a id="block-cipher-twofish"></a>`Twofish` | `mcrypto.ciphers.dispatch.process` | `Twofish/ECB`<br>`Twofish/CBC`<br>`Twofish/CBC-CTS`<br>`Twofish/CFB`<br>`Twofish/OFB`<br>`Twofish/CTR` | [Use and example](../algorithms/by-name/block-cipher.md#block-cipher-twofish) | [Guide](../algorithms/by-name/block-cipher.md) | `available` | — |
| <a id="block-cipher-serpent"></a>`Serpent` | `mcrypto.ciphers.dispatch.process` | `Serpent/ECB`<br>`Serpent/CBC`<br>`Serpent/CBC-CTS`<br>`Serpent/CFB`<br>`Serpent/OFB`<br>`Serpent/CTR` | [Use and example](../algorithms/by-name/block-cipher.md#block-cipher-serpent) | [Guide](../algorithms/by-name/block-cipher.md) | `available` | — |
| <a id="block-cipher-cast-128"></a>`CAST-128` | `mcrypto.ciphers.dispatch.process` | `CAST-128/ECB`<br>`CAST-128/CBC`<br>`CAST-128/CBC-CTS`<br>`CAST-128/CFB`<br>`CAST-128/OFB`<br>`CAST-128/CTR` | [Use and example](../algorithms/by-name/block-cipher.md#block-cipher-cast-128) | [Guide](../algorithms/by-name/block-cipher.md) | `available` | — |
| <a id="block-cipher-cast-256"></a>`CAST-256` | `mcrypto.ciphers.dispatch.process` | `CAST-256/ECB`<br>`CAST-256/CBC`<br>`CAST-256/CBC-CTS`<br>`CAST-256/CFB`<br>`CAST-256/OFB`<br>`CAST-256/CTR` | [Use and example](../algorithms/by-name/block-cipher.md#block-cipher-cast-256) | [Guide](../algorithms/by-name/block-cipher.md) | `available` | — |
| <a id="block-cipher-aria"></a>`ARIA` | `mcrypto.ciphers.dispatch.process` | `ARIA/ECB`<br>`ARIA/CBC`<br>`ARIA/CBC-CTS`<br>`ARIA/CFB`<br>`ARIA/OFB`<br>`ARIA/CTR` | [Use and example](../algorithms/by-name/block-cipher.md#block-cipher-aria) | [Guide](../algorithms/by-name/block-cipher.md) | `available` | — |
| <a id="block-cipher-blowfish"></a>`Blowfish` | `mcrypto.ciphers.dispatch.process` | `Blowfish/ECB`<br>`Blowfish/CBC`<br>`Blowfish/CBC-CTS`<br>`Blowfish/CFB`<br>`Blowfish/OFB`<br>`Blowfish/CTR` | [Use and example](../algorithms/by-name/block-cipher.md#block-cipher-blowfish) | [Guide](../algorithms/by-name/block-cipher.md) | `available` | — |
| <a id="block-cipher-camellia"></a>`Camellia` | `mcrypto.ciphers.dispatch.process` | `Camellia/ECB`<br>`Camellia/CBC`<br>`Camellia/CBC-CTS`<br>`Camellia/CFB`<br>`Camellia/OFB`<br>`Camellia/CTR` | [Use and example](../algorithms/by-name/block-cipher.md#block-cipher-camellia) | [Guide](../algorithms/by-name/block-cipher.md) | `available` | — |
| <a id="block-cipher-cham-64"></a>`CHAM-64` | `mcrypto.ciphers.dispatch.process` | `CHAM-64/ECB`<br>`CHAM-64/CBC`<br>`CHAM-64/CBC-CTS`<br>`CHAM-64/CFB`<br>`CHAM-64/OFB`<br>`CHAM-64/CTR` | [Use and example](../algorithms/by-name/block-cipher.md#block-cipher-cham-64) | [Guide](../algorithms/by-name/block-cipher.md) | `available` | — |
| <a id="block-cipher-cham-128"></a>`CHAM-128` | `mcrypto.ciphers.dispatch.process` | `CHAM-128/ECB`<br>`CHAM-128/CBC`<br>`CHAM-128/CBC-CTS`<br>`CHAM-128/CFB`<br>`CHAM-128/OFB`<br>`CHAM-128/CTR` | [Use and example](../algorithms/by-name/block-cipher.md#block-cipher-cham-128) | [Guide](../algorithms/by-name/block-cipher.md) | `available` | — |
| <a id="block-cipher-des"></a>`DES` | `mcrypto.ciphers.dispatch.process` | `DES/ECB`<br>`DES/CBC`<br>`DES/CBC-CTS`<br>`DES/CFB`<br>`DES/OFB`<br>`DES/CTR` | [Use and example](../algorithms/by-name/block-cipher.md#block-cipher-des) | [Guide](../algorithms/by-name/block-cipher.md) | `available` | — |
| <a id="block-cipher-des-xex3"></a>`DES-XEX3` | `mcrypto.ciphers.dispatch.process` | `DES-XEX3/ECB`<br>`DES-XEX3/CBC`<br>`DES-XEX3/CBC-CTS`<br>`DES-XEX3/CFB`<br>`DES-XEX3/OFB`<br>`DES-XEX3/CTR` | [Use and example](../algorithms/by-name/block-cipher.md#block-cipher-des-xex3) | [Guide](../algorithms/by-name/block-cipher.md) | `available` | — |
| <a id="block-cipher-des-ede2"></a>`DES-EDE2` | `mcrypto.ciphers.dispatch.process` | `DES-EDE2/ECB`<br>`DES-EDE2/CBC`<br>`DES-EDE2/CBC-CTS`<br>`DES-EDE2/CFB`<br>`DES-EDE2/OFB`<br>`DES-EDE2/CTR` | [Use and example](../algorithms/by-name/block-cipher.md#block-cipher-des-ede2) | [Guide](../algorithms/by-name/block-cipher.md) | `available` | — |
| <a id="block-cipher-des-ede3"></a>`DES-EDE3` | `mcrypto.ciphers.dispatch.process` | `DES-EDE3/ECB`<br>`DES-EDE3/CBC`<br>`DES-EDE3/CBC-CTS`<br>`DES-EDE3/CFB`<br>`DES-EDE3/OFB`<br>`DES-EDE3/CTR` | [Use and example](../algorithms/by-name/block-cipher.md#block-cipher-des-ede3) | [Guide](../algorithms/by-name/block-cipher.md) | `available` | — |
| <a id="block-cipher-3-way"></a>`3-WAY` | `mcrypto.ciphers.dispatch.process` | `3-WAY/ECB`<br>`3-WAY/CBC`<br>`3-WAY/CBC-CTS`<br>`3-WAY/CFB`<br>`3-WAY/OFB`<br>`3-WAY/CTR` | [Use and example](../algorithms/by-name/block-cipher.md#block-cipher-3-way) | [Guide](../algorithms/by-name/block-cipher.md) | `available` | — |
| <a id="block-cipher-gost"></a>`GOST` | `mcrypto.ciphers.dispatch.process` | `GOST/ECB`<br>`GOST/CBC`<br>`GOST/CBC-CTS`<br>`GOST/CFB`<br>`GOST/OFB`<br>`GOST/CTR` | [Use and example](../algorithms/by-name/block-cipher.md#block-cipher-gost) | [Guide](../algorithms/by-name/block-cipher.md) | `available` | — |
| <a id="block-cipher-hight"></a>`HIGHT` | `mcrypto.ciphers.dispatch.process` | `HIGHT/ECB`<br>`HIGHT/CBC`<br>`HIGHT/CBC-CTS`<br>`HIGHT/CFB`<br>`HIGHT/OFB`<br>`HIGHT/CTR` | [Use and example](../algorithms/by-name/block-cipher.md#block-cipher-hight) | [Guide](../algorithms/by-name/block-cipher.md) | `available` | — |
| <a id="block-cipher-idea"></a>`IDEA` | `mcrypto.ciphers.dispatch.process` | `IDEA/ECB`<br>`IDEA/CBC`<br>`IDEA/CBC-CTS`<br>`IDEA/CFB`<br>`IDEA/OFB`<br>`IDEA/CTR` | [Use and example](../algorithms/by-name/block-cipher.md#block-cipher-idea) | [Guide](../algorithms/by-name/block-cipher.md) | `available` | — |
| <a id="block-cipher-kalyna-128"></a>`Kalyna-128` | `mcrypto.ciphers.dispatch.process` | `Kalyna-128/ECB`<br>`Kalyna-128/CBC`<br>`Kalyna-128/CBC-CTS`<br>`Kalyna-128/CFB`<br>`Kalyna-128/OFB`<br>`Kalyna-128/CTR` | [Use and example](../algorithms/by-name/block-cipher.md#block-cipher-kalyna-128) | [Guide](../algorithms/by-name/block-cipher.md) | `available` | — |
| <a id="block-cipher-kalyna-256"></a>`Kalyna-256` | `mcrypto.ciphers.dispatch.process` | `Kalyna-256/ECB`<br>`Kalyna-256/CBC`<br>`Kalyna-256/CBC-CTS`<br>`Kalyna-256/CFB`<br>`Kalyna-256/OFB`<br>`Kalyna-256/CTR` | [Use and example](../algorithms/by-name/block-cipher.md#block-cipher-kalyna-256) | [Guide](../algorithms/by-name/block-cipher.md) | `available` | — |
| <a id="block-cipher-kalyna-512"></a>`Kalyna-512` | `mcrypto.ciphers.dispatch.process` | `Kalyna-512/ECB`<br>`Kalyna-512/CBC`<br>`Kalyna-512/CBC-CTS`<br>`Kalyna-512/CFB`<br>`Kalyna-512/OFB`<br>`Kalyna-512/CTR` | [Use and example](../algorithms/by-name/block-cipher.md#block-cipher-kalyna-512) | [Guide](../algorithms/by-name/block-cipher.md) | `available` | — |
| <a id="block-cipher-lea"></a>`LEA` | `mcrypto.ciphers.dispatch.process` | `LEA/ECB`<br>`LEA/CBC`<br>`LEA/CBC-CTS`<br>`LEA/CFB`<br>`LEA/OFB`<br>`LEA/CTR` | [Use and example](../algorithms/by-name/block-cipher.md#block-cipher-lea) | [Guide](../algorithms/by-name/block-cipher.md) | `available` | — |
| <a id="block-cipher-safer"></a>`SAFER` | `mcrypto.ciphers.dispatch.process` | `SAFER/ECB`<br>`SAFER/CBC`<br>`SAFER/CBC-CTS`<br>`SAFER/CFB`<br>`SAFER/OFB`<br>`SAFER/CTR` | [Use and example](../algorithms/by-name/block-cipher.md#block-cipher-safer) | [Guide](../algorithms/by-name/block-cipher.md) | `available` | — |
| <a id="block-cipher-seed"></a>`SEED` | `mcrypto.ciphers.dispatch.process` | `SEED/ECB`<br>`SEED/CBC`<br>`SEED/CBC-CTS`<br>`SEED/CFB`<br>`SEED/OFB`<br>`SEED/CTR` | [Use and example](../algorithms/by-name/block-cipher.md#block-cipher-seed) | [Guide](../algorithms/by-name/block-cipher.md) | `available` | — |
| <a id="block-cipher-shacal-2"></a>`SHACAL-2` | `mcrypto.ciphers.dispatch.process` | `SHACAL-2/ECB`<br>`SHACAL-2/CBC`<br>`SHACAL-2/CBC-CTS`<br>`SHACAL-2/CFB`<br>`SHACAL-2/OFB`<br>`SHACAL-2/CTR` | [Use and example](../algorithms/by-name/block-cipher.md#block-cipher-shacal-2) | [Guide](../algorithms/by-name/block-cipher.md) | `available` | — |
| <a id="block-cipher-shark"></a>`SHARK` | `mcrypto.ciphers.dispatch.process` | `SHARK/ECB`<br>`SHARK/CBC`<br>`SHARK/CBC-CTS`<br>`SHARK/CFB`<br>`SHARK/OFB`<br>`SHARK/CTR` | [Use and example](../algorithms/by-name/block-cipher.md#block-cipher-shark) | [Guide](../algorithms/by-name/block-cipher.md) | `available` | — |
| <a id="block-cipher-simeck-32"></a>`SIMECK-32` | `mcrypto.ciphers.dispatch.process` | `SIMECK-32/ECB`<br>`SIMECK-32/CBC`<br>`SIMECK-32/CBC-CTS`<br>`SIMECK-32/CFB`<br>`SIMECK-32/OFB`<br>`SIMECK-32/CTR` | [Use and example](../algorithms/by-name/block-cipher.md#block-cipher-simeck-32) | [Guide](../algorithms/by-name/block-cipher.md) | `available` | — |
| <a id="block-cipher-simeck-64"></a>`SIMECK-64` | `mcrypto.ciphers.dispatch.process` | `SIMECK-64/ECB`<br>`SIMECK-64/CBC`<br>`SIMECK-64/CBC-CTS`<br>`SIMECK-64/CFB`<br>`SIMECK-64/OFB`<br>`SIMECK-64/CTR` | [Use and example](../algorithms/by-name/block-cipher.md#block-cipher-simeck-64) | [Guide](../algorithms/by-name/block-cipher.md) | `available` | — |
| <a id="block-cipher-simon-64"></a>`SIMON-64` | `mcrypto.ciphers.dispatch.process` | `SIMON-64/ECB`<br>`SIMON-64/CBC`<br>`SIMON-64/CBC-CTS`<br>`SIMON-64/CFB`<br>`SIMON-64/OFB`<br>`SIMON-64/CTR` | [Use and example](../algorithms/by-name/block-cipher.md#block-cipher-simon-64) | [Guide](../algorithms/by-name/block-cipher.md) | `available` | — |
| <a id="block-cipher-simon-128"></a>`SIMON-128` | `mcrypto.ciphers.dispatch.process` | `SIMON-128/ECB`<br>`SIMON-128/CBC`<br>`SIMON-128/CBC-CTS`<br>`SIMON-128/CFB`<br>`SIMON-128/OFB`<br>`SIMON-128/CTR` | [Use and example](../algorithms/by-name/block-cipher.md#block-cipher-simon-128) | [Guide](../algorithms/by-name/block-cipher.md) | `available` | — |
| <a id="block-cipher-skipjack"></a>`Skipjack` | `mcrypto.ciphers.dispatch.process` | `Skipjack/ECB`<br>`Skipjack/CBC`<br>`Skipjack/CBC-CTS`<br>`Skipjack/CFB`<br>`Skipjack/OFB`<br>`Skipjack/CTR` | [Use and example](../algorithms/by-name/block-cipher.md#block-cipher-skipjack) | [Guide](../algorithms/by-name/block-cipher.md) | `available` | — |
| <a id="block-cipher-speck-64"></a>`SPECK-64` | `mcrypto.ciphers.dispatch.process` | `SPECK-64/ECB`<br>`SPECK-64/CBC`<br>`SPECK-64/CBC-CTS`<br>`SPECK-64/CFB`<br>`SPECK-64/OFB`<br>`SPECK-64/CTR` | [Use and example](../algorithms/by-name/block-cipher.md#block-cipher-speck-64) | [Guide](../algorithms/by-name/block-cipher.md) | `available` | — |
| <a id="block-cipher-speck-128"></a>`SPECK-128` | `mcrypto.ciphers.dispatch.process` | `SPECK-128/ECB`<br>`SPECK-128/CBC`<br>`SPECK-128/CBC-CTS`<br>`SPECK-128/CFB`<br>`SPECK-128/OFB`<br>`SPECK-128/CTR` | [Use and example](../algorithms/by-name/block-cipher.md#block-cipher-speck-128) | [Guide](../algorithms/by-name/block-cipher.md) | `available` | — |
| <a id="block-cipher-sm4"></a>`SM4` | `mcrypto.ciphers.dispatch.process` | `SM4/ECB`<br>`SM4/CBC`<br>`SM4/CBC-CTS`<br>`SM4/CFB`<br>`SM4/OFB`<br>`SM4/CTR` | [Use and example](../algorithms/by-name/block-cipher.md#block-cipher-sm4) | [Guide](../algorithms/by-name/block-cipher.md) | `available` | — |
| <a id="block-cipher-square"></a>`Square` | `mcrypto.ciphers.dispatch.process` | `Square/ECB`<br>`Square/CBC`<br>`Square/CBC-CTS`<br>`Square/CFB`<br>`Square/OFB`<br>`Square/CTR` | [Use and example](../algorithms/by-name/block-cipher.md#block-cipher-square) | [Guide](../algorithms/by-name/block-cipher.md) | `available` | — |
| <a id="block-cipher-tea"></a>`TEA` | `mcrypto.ciphers.dispatch.process` | `TEA/ECB`<br>`TEA/CBC`<br>`TEA/CBC-CTS`<br>`TEA/CFB`<br>`TEA/OFB`<br>`TEA/CTR` | [Use and example](../algorithms/by-name/block-cipher.md#block-cipher-tea) | [Guide](../algorithms/by-name/block-cipher.md) | `available` | — |
| <a id="block-cipher-threefish-256"></a>`Threefish-256` | `mcrypto.ciphers.dispatch.process` | `Threefish-256/ECB`<br>`Threefish-256/CBC`<br>`Threefish-256/CBC-CTS`<br>`Threefish-256/CFB`<br>`Threefish-256/OFB`<br>`Threefish-256/CTR`<br>`Threefish-256/XTS` | [Use and example](../algorithms/by-name/block-cipher.md#block-cipher-threefish-256) | [Guide](../algorithms/by-name/block-cipher.md) | `available` | — |
| <a id="block-cipher-threefish-512"></a>`Threefish-512` | `mcrypto.ciphers.dispatch.process` | `Threefish-512/ECB`<br>`Threefish-512/CBC`<br>`Threefish-512/CBC-CTS`<br>`Threefish-512/CFB`<br>`Threefish-512/OFB`<br>`Threefish-512/CTR`<br>`Threefish-512/XTS` | [Use and example](../algorithms/by-name/block-cipher.md#block-cipher-threefish-512) | [Guide](../algorithms/by-name/block-cipher.md) | `available` | — |
| <a id="block-cipher-threefish-1024"></a>`Threefish-1024` | `mcrypto.ciphers.dispatch.process` | `Threefish-1024/ECB`<br>`Threefish-1024/CBC`<br>`Threefish-1024/CBC-CTS`<br>`Threefish-1024/CFB`<br>`Threefish-1024/OFB`<br>`Threefish-1024/CTR`<br>`Threefish-1024/XTS` | [Use and example](../algorithms/by-name/block-cipher.md#block-cipher-threefish-1024) | [Guide](../algorithms/by-name/block-cipher.md) | `available` | — |
| <a id="block-cipher-xtea"></a>`XTEA` | `mcrypto.ciphers.dispatch.process` | `XTEA/ECB`<br>`XTEA/CBC`<br>`XTEA/CBC-CTS`<br>`XTEA/CFB`<br>`XTEA/OFB`<br>`XTEA/CTR` | [Use and example](../algorithms/by-name/block-cipher.md#block-cipher-xtea) | [Guide](../algorithms/by-name/block-cipher.md) | `available` | — |

## Cipher modes

| Algorithm | Public API/import | Selector or operation | Individual use and example | Family guide | Availability | Note |
|:--|:--|:--|:--|:--|:--|:--|
| <a id="cipher-mode-ecb"></a>`ECB` | `mcrypto.ciphers.dispatch.process` | `AES/ECB` | [Use and example](../algorithms/by-name/cipher-mode.md#cipher-mode-ecb) | [Guide](../algorithms/by-name/cipher-mode.md) | `available` | — |
| <a id="cipher-mode-cbc"></a>`CBC` | `mcrypto.ciphers.dispatch.process` | `AES/CBC` | [Use and example](../algorithms/by-name/cipher-mode.md#cipher-mode-cbc) | [Guide](../algorithms/by-name/cipher-mode.md) | `available` | — |
| <a id="cipher-mode-cbc-cts"></a>`CBC-CTS` | `mcrypto.ciphers.dispatch.process` | `AES/CBC-CTS` | [Use and example](../algorithms/by-name/cipher-mode.md#cipher-mode-cbc-cts) | [Guide](../algorithms/by-name/cipher-mode.md) | `available` | — |
| <a id="cipher-mode-cfb"></a>`CFB` | `mcrypto.ciphers.dispatch.process` | `AES/CFB` | [Use and example](../algorithms/by-name/cipher-mode.md#cipher-mode-cfb) | [Guide](../algorithms/by-name/cipher-mode.md) | `available` | — |
| <a id="cipher-mode-ofb"></a>`OFB` | `mcrypto.ciphers.dispatch.process` | `AES/OFB` | [Use and example](../algorithms/by-name/cipher-mode.md#cipher-mode-ofb) | [Guide](../algorithms/by-name/cipher-mode.md) | `available` | — |
| <a id="cipher-mode-ctr"></a>`CTR` | `mcrypto.ciphers.dispatch.process` | `AES/CTR` | [Use and example](../algorithms/by-name/cipher-mode.md#cipher-mode-ctr) | [Guide](../algorithms/by-name/cipher-mode.md) | `available` | — |
| <a id="cipher-mode-xts"></a>`XTS` | `mcrypto.ciphers.dispatch.process`<br>`mcrypto.ciphers.xts.process` | `AES/XTS` | [Use and example](../algorithms/by-name/cipher-mode.md#cipher-mode-xts) | [Guide](../algorithms/by-name/cipher-mode.md) | `available` | — |

## MACs and short hashes

| Algorithm | Public API/import | Selector or operation | Individual use and example | Family guide | Availability | Note |
|:--|:--|:--|:--|:--|:--|:--|
| <a id="mac-blake2s-mac"></a>`BLAKE2s-MAC` | `mcrypto.macs.dispatch.authenticate` | `BLAKE2s-MAC` | [Use and example](../algorithms/by-name/mac.md#mac-blake2s-mac) | [Guide](../algorithms/by-name/mac.md) | `available` | — |
| <a id="mac-blake2b-mac"></a>`BLAKE2b-MAC` | `mcrypto.macs.dispatch.authenticate` | `BLAKE2b-MAC` | [Use and example](../algorithms/by-name/mac.md#mac-blake2b-mac) | [Guide](../algorithms/by-name/mac.md) | `available` | — |
| <a id="mac-cbc-mac"></a>`CBC-MAC` | `mcrypto.macs.dispatch.authenticate`<br>`mcrypto.macs.cbc_mac.verify` | `CBC-MAC`<br>`CBC-MAC(AES)` | [Use and example](../algorithms/by-name/mac.md#mac-cbc-mac) | [Guide](../algorithms/by-name/mac.md) | `available` | — |
| <a id="mac-cmac"></a>`CMAC` | `mcrypto.macs.dispatch.authenticate`<br>`mcrypto.macs.cmac.verify` | `CMAC`<br>`CMAC(AES)` | [Use and example](../algorithms/by-name/mac.md#mac-cmac) | [Guide](../algorithms/by-name/mac.md) | `available` | — |
| <a id="mac-dmac"></a>`DMAC` | `mcrypto.macs.dispatch.authenticate`<br>`mcrypto.macs.dmac.verify` | `DMAC`<br>`DMAC(AES)` | [Use and example](../algorithms/by-name/mac.md#mac-dmac) | [Guide](../algorithms/by-name/mac.md) | `available` | — |
| <a id="mac-gmac"></a>`GMAC` | `mcrypto.macs.gmac.authenticate` | `GMAC`<br>`GMAC(AES)` | [Use and example](../algorithms/by-name/mac.md#mac-gmac) | [Guide](../algorithms/by-name/mac.md) | `available` | — |
| <a id="mac-hmac"></a>`HMAC` | `mcrypto.macs.dispatch.authenticate` | `HMAC`<br>`HMAC(SHA-1)`<br>`HMAC-SHA1`<br>`HMAC-RIPEMD160` | [Use and example](../algorithms/by-name/mac.md#mac-hmac) | [Guide](../algorithms/by-name/mac.md) | `available` | — |
| <a id="mac-panamamac"></a>`PanamaMAC` | `mcrypto.macs.dispatch.authenticate` | `PanamaMAC` | [Use and example](../algorithms/by-name/mac.md#mac-panamamac) | [Guide](../algorithms/by-name/mac.md) | `available` | — |
| <a id="mac-poly1305-aes"></a>`Poly1305-AES` | `mcrypto.macs.poly1305_aes.authenticate` | `Poly1305-AES` | [Use and example](../algorithms/by-name/mac.md#mac-poly1305-aes) | [Guide](../algorithms/by-name/mac.md) | `available` | — |
| <a id="mac-poly1305"></a>`Poly1305` | `mcrypto.macs.dispatch.authenticate`<br>`mcrypto.macs.poly1305.authenticate` | `Poly1305` | [Use and example](../algorithms/by-name/mac.md#mac-poly1305) | [Guide](../algorithms/by-name/mac.md) | `available` | — |
| <a id="mac-ripemd160-hmac"></a>`RIPEMD160-HMAC` | `mcrypto.macs.dispatch.authenticate` | `RIPEMD160-HMAC` | [Use and example](../algorithms/by-name/mac.md#mac-ripemd160-hmac) | [Guide](../algorithms/by-name/mac.md) | `available` | — |
| <a id="mac-siphash-2-4"></a>`SipHash-2-4` | `mcrypto.macs.dispatch.authenticate`<br>`mcrypto.macs.siphash.hash` | `SipHash-2-4` | [Use and example](../algorithms/by-name/mac.md#mac-siphash-2-4) | [Guide](../algorithms/by-name/mac.md) | `available` | — |
| <a id="mac-siphash-4-8"></a>`SipHash-4-8` | `mcrypto.macs.dispatch.authenticate`<br>`mcrypto.macs.siphash.hash` | `SipHash-4-8` | [Use and example](../algorithms/by-name/mac.md#mac-siphash-4-8) | [Guide](../algorithms/by-name/mac.md) | `available` | — |
| <a id="mac-two-track-mac"></a>`Two-Track-MAC` | `mcrypto.macs.dispatch.authenticate` | `Two-Track-MAC` | [Use and example](../algorithms/by-name/mac.md#mac-two-track-mac) | [Guide](../algorithms/by-name/mac.md) | `available` | — |
| <a id="mac-vmac"></a>`VMAC` | `mcrypto.macs.vmac.authenticate` | `VMAC` | [Use and example](../algorithms/by-name/mac.md#mac-vmac) | [Guide](../algorithms/by-name/mac.md) | `available` | — |
| <a id="mac-siphash"></a>`SipHash` | `mcrypto.macs.siphash.hash`<br>`mcrypto.macs.siphash.hash_into` | `parameterized SipHash` | [Use and example](../algorithms/by-name/mac.md#mac-siphash) | [Guide](../algorithms/by-name/mac.md) | `composed` | Parameterized SipHash API; choose a concrete SipHash selector rather than the fixed-digest dispatcher. |
| <a id="mac-hmac-sha256"></a>`HMAC-SHA256` | `mcrypto.macs.dispatch.authenticate` | `HMAC(SHA-256)`<br>`HMAC-SHA256` | [Use and example](../algorithms/by-name/mac.md#mac-hmac-sha256) | [Guide](../algorithms/by-name/mac.md) | `available` | — |
| <a id="mac-hmac-sha512"></a>`HMAC-SHA512` | `mcrypto.macs.dispatch.authenticate` | `HMAC(SHA-512)`<br>`HMAC-SHA512` | [Use and example](../algorithms/by-name/mac.md#mac-hmac-sha512) | [Guide](../algorithms/by-name/mac.md) | `available` | — |
| <a id="mac-hmac-sha512-256"></a>`HMAC-SHA512-256` | `mcrypto.macs.dispatch.authenticate` | `HMAC-SHA512-256` | [Use and example](../algorithms/by-name/mac.md#mac-hmac-sha512-256) | [Guide](../algorithms/by-name/mac.md) | `available` | — |
| <a id="mac-siphash-x-2-4"></a>`SipHash-x-2-4` | `mcrypto.macs.dispatch.authenticate`<br>`mcrypto.macs.siphash.hash` | `SipHash-x-2-4` | [Use and example](../algorithms/by-name/mac.md#mac-siphash-x-2-4) | [Guide](../algorithms/by-name/mac.md) | `available` | — |

## Hashes

| Algorithm | Public API/import | Selector or operation | Individual use and example | Family guide | Availability | Note |
|:--|:--|:--|:--|:--|:--|:--|
| <a id="hash-adler32"></a>`Adler32` | `mcrypto.hashes.dispatch.hash`<br>`mcrypto.hashes.dispatch.hash_into` | `Adler32` | [Use and example](../algorithms/by-name/hash.md#hash-adler32) | [Guide](../algorithms/by-name/hash.md) | `available` | — |
| <a id="hash-crc32"></a>`CRC32` | `mcrypto.hashes.dispatch.hash`<br>`mcrypto.hashes.dispatch.hash_into` | `CRC32` | [Use and example](../algorithms/by-name/hash.md#hash-crc32) | [Guide](../algorithms/by-name/hash.md) | `available` | — |
| <a id="hash-crc32c"></a>`CRC32C` | `mcrypto.hashes.dispatch.hash`<br>`mcrypto.hashes.dispatch.hash_into` | `CRC32C` | [Use and example](../algorithms/by-name/hash.md#hash-crc32c) | [Guide](../algorithms/by-name/hash.md) | `available` | — |
| <a id="hash-md2"></a>`MD2` | `mcrypto.hashes.dispatch.hash`<br>`mcrypto.hashes.dispatch.hash_into` | `MD2` | [Use and example](../algorithms/by-name/hash.md#hash-md2) | [Guide](../algorithms/by-name/hash.md) | `available` | — |
| <a id="hash-md4"></a>`MD4` | `mcrypto.hashes.dispatch.hash`<br>`mcrypto.hashes.dispatch.hash_into` | `MD4` | [Use and example](../algorithms/by-name/hash.md#hash-md4) | [Guide](../algorithms/by-name/hash.md) | `available` | — |
| <a id="hash-md5"></a>`MD5` | `mcrypto.hashes.dispatch.hash`<br>`mcrypto.hashes.dispatch.hash_into` | `MD5` | [Use and example](../algorithms/by-name/hash.md#hash-md5) | [Guide](../algorithms/by-name/hash.md) | `available` | — |
| <a id="hash-blake2s"></a>`BLAKE2s` | `mcrypto.hashes.dispatch.hash`<br>`mcrypto.hashes.dispatch.hash_into` | `BLAKE2s` | [Use and example](../algorithms/by-name/hash.md#hash-blake2s) | [Guide](../algorithms/by-name/hash.md) | `available` | — |
| <a id="hash-blake2b"></a>`BLAKE2b` | `mcrypto.hashes.dispatch.hash`<br>`mcrypto.hashes.dispatch.hash_into` | `BLAKE2b` | [Use and example](../algorithms/by-name/hash.md#hash-blake2b) | [Guide](../algorithms/by-name/hash.md) | `available` | — |
| <a id="hash-keccak-224"></a>`Keccak-224` | `mcrypto.hashes.dispatch.hash`<br>`mcrypto.hashes.dispatch.hash_into` | `Keccak-224` | [Use and example](../algorithms/by-name/hash.md#hash-keccak-224) | [Guide](../algorithms/by-name/hash.md) | `available` | — |
| <a id="hash-keccak-256"></a>`Keccak-256` | `mcrypto.hashes.dispatch.hash`<br>`mcrypto.hashes.dispatch.hash_into` | `Keccak-256` | [Use and example](../algorithms/by-name/hash.md#hash-keccak-256) | [Guide](../algorithms/by-name/hash.md) | `available` | — |
| <a id="hash-keccak-384"></a>`Keccak-384` | `mcrypto.hashes.dispatch.hash`<br>`mcrypto.hashes.dispatch.hash_into` | `Keccak-384` | [Use and example](../algorithms/by-name/hash.md#hash-keccak-384) | [Guide](../algorithms/by-name/hash.md) | `available` | — |
| <a id="hash-keccak-512"></a>`Keccak-512` | `mcrypto.hashes.dispatch.hash`<br>`mcrypto.hashes.dispatch.hash_into` | `Keccak-512` | [Use and example](../algorithms/by-name/hash.md#hash-keccak-512) | [Guide](../algorithms/by-name/hash.md) | `available` | — |
| <a id="hash-lsh-224"></a>`LSH-224` | `mcrypto.hashes.dispatch.hash`<br>`mcrypto.hashes.dispatch.hash_into` | `LSH-224` | [Use and example](../algorithms/by-name/hash.md#hash-lsh-224) | [Guide](../algorithms/by-name/hash.md) | `available` | — |
| <a id="hash-lsh-256"></a>`LSH-256` | `mcrypto.hashes.dispatch.hash`<br>`mcrypto.hashes.dispatch.hash_into` | `LSH-256` | [Use and example](../algorithms/by-name/hash.md#hash-lsh-256) | [Guide](../algorithms/by-name/hash.md) | `available` | — |
| <a id="hash-lsh-384"></a>`LSH-384` | `mcrypto.hashes.dispatch.hash`<br>`mcrypto.hashes.dispatch.hash_into` | `LSH-384` | [Use and example](../algorithms/by-name/hash.md#hash-lsh-384) | [Guide](../algorithms/by-name/hash.md) | `available` | — |
| <a id="hash-lsh-512"></a>`LSH-512` | `mcrypto.hashes.dispatch.hash`<br>`mcrypto.hashes.dispatch.hash_into` | `LSH-512` | [Use and example](../algorithms/by-name/hash.md#hash-lsh-512) | [Guide](../algorithms/by-name/hash.md) | `available` | — |
| <a id="hash-lsh-512-256"></a>`LSH-512-256` | `mcrypto.hashes.dispatch.hash`<br>`mcrypto.hashes.dispatch.hash_into` | `LSH-512-256` | [Use and example](../algorithms/by-name/hash.md#hash-lsh-512-256) | [Guide](../algorithms/by-name/hash.md) | `available` | — |
| <a id="hash-panamahash"></a>`PanamaHash` | `mcrypto.hashes.dispatch.hash`<br>`mcrypto.hashes.dispatch.hash_into` | `PanamaHash` | [Use and example](../algorithms/by-name/hash.md#hash-panamahash) | [Guide](../algorithms/by-name/hash.md) | `available` | — |
| <a id="hash-ripemd-128"></a>`RIPEMD-128` | `mcrypto.hashes.dispatch.hash`<br>`mcrypto.hashes.dispatch.hash_into` | `RIPEMD-128` | [Use and example](../algorithms/by-name/hash.md#hash-ripemd-128) | [Guide](../algorithms/by-name/hash.md) | `available` | — |
| <a id="hash-ripemd-160"></a>`RIPEMD-160` | `mcrypto.hashes.dispatch.hash`<br>`mcrypto.hashes.dispatch.hash_into` | `RIPEMD-160` | [Use and example](../algorithms/by-name/hash.md#hash-ripemd-160) | [Guide](../algorithms/by-name/hash.md) | `available` | — |
| <a id="hash-ripemd-256"></a>`RIPEMD-256` | `mcrypto.hashes.dispatch.hash`<br>`mcrypto.hashes.dispatch.hash_into` | `RIPEMD-256` | [Use and example](../algorithms/by-name/hash.md#hash-ripemd-256) | [Guide](../algorithms/by-name/hash.md) | `available` | — |
| <a id="hash-ripemd-320"></a>`RIPEMD-320` | `mcrypto.hashes.dispatch.hash`<br>`mcrypto.hashes.dispatch.hash_into` | `RIPEMD-320` | [Use and example](../algorithms/by-name/hash.md#hash-ripemd-320) | [Guide](../algorithms/by-name/hash.md) | `available` | — |
| <a id="hash-sha-1"></a>`SHA-1` | `mcrypto.hashes.dispatch.hash`<br>`mcrypto.hashes.dispatch.hash_into` | `SHA-1` | [Use and example](../algorithms/by-name/hash.md#hash-sha-1) | [Guide](../algorithms/by-name/hash.md) | `available` | — |
| <a id="hash-sha-224"></a>`SHA-224` | `mcrypto.hashes.dispatch.hash`<br>`mcrypto.hashes.dispatch.hash_into` | `SHA-224` | [Use and example](../algorithms/by-name/hash.md#hash-sha-224) | [Guide](../algorithms/by-name/hash.md) | `available` | — |
| <a id="hash-sha-256"></a>`SHA-256` | `mcrypto.hashes.dispatch.hash`<br>`mcrypto.hashes.dispatch.hash_into` | `SHA-256` | [Use and example](../algorithms/by-name/hash.md#hash-sha-256) | [Guide](../algorithms/by-name/hash.md) | `available` | — |
| <a id="hash-sha-384"></a>`SHA-384` | `mcrypto.hashes.dispatch.hash`<br>`mcrypto.hashes.dispatch.hash_into` | `SHA-384` | [Use and example](../algorithms/by-name/hash.md#hash-sha-384) | [Guide](../algorithms/by-name/hash.md) | `available` | — |
| <a id="hash-sha-512"></a>`SHA-512` | `mcrypto.hashes.dispatch.hash`<br>`mcrypto.hashes.dispatch.hash_into` | `SHA-512` | [Use and example](../algorithms/by-name/hash.md#hash-sha-512) | [Guide](../algorithms/by-name/hash.md) | `available` | — |
| <a id="hash-sha3-224"></a>`SHA3-224` | `mcrypto.hashes.dispatch.hash`<br>`mcrypto.hashes.dispatch.hash_into` | `SHA3-224` | [Use and example](../algorithms/by-name/hash.md#hash-sha3-224) | [Guide](../algorithms/by-name/hash.md) | `available` | — |
| <a id="hash-sha3-256"></a>`SHA3-256` | `mcrypto.hashes.dispatch.hash`<br>`mcrypto.hashes.dispatch.hash_into` | `SHA3-256` | [Use and example](../algorithms/by-name/hash.md#hash-sha3-256) | [Guide](../algorithms/by-name/hash.md) | `available` | — |
| <a id="hash-sha3-384"></a>`SHA3-384` | `mcrypto.hashes.dispatch.hash`<br>`mcrypto.hashes.dispatch.hash_into` | `SHA3-384` | [Use and example](../algorithms/by-name/hash.md#hash-sha3-384) | [Guide](../algorithms/by-name/hash.md) | `available` | — |
| <a id="hash-sha3-512"></a>`SHA3-512` | `mcrypto.hashes.dispatch.hash`<br>`mcrypto.hashes.dispatch.hash_into` | `SHA3-512` | [Use and example](../algorithms/by-name/hash.md#hash-sha3-512) | [Guide](../algorithms/by-name/hash.md) | `available` | — |
| <a id="hash-sm3"></a>`SM3` | `mcrypto.hashes.dispatch.hash`<br>`mcrypto.hashes.dispatch.hash_into` | `SM3` | [Use and example](../algorithms/by-name/hash.md#hash-sm3) | [Guide](../algorithms/by-name/hash.md) | `available` | — |
| <a id="hash-tiger"></a>`Tiger` | `mcrypto.hashes.dispatch.hash`<br>`mcrypto.hashes.dispatch.hash_into` | `Tiger` | [Use and example](../algorithms/by-name/hash.md#hash-tiger) | [Guide](../algorithms/by-name/hash.md) | `available` | — |
| <a id="hash-whirlpool"></a>`Whirlpool` | `mcrypto.hashes.dispatch.hash`<br>`mcrypto.hashes.dispatch.hash_into` | `Whirlpool` | [Use and example](../algorithms/by-name/hash.md#hash-whirlpool) | [Guide](../algorithms/by-name/hash.md) | `available` | — |

## XOFs

| Algorithm | Public API/import | Selector or operation | Individual use and example | Family guide | Availability | Note |
|:--|:--|:--|:--|:--|:--|:--|
| <a id="xof-shake128"></a>`SHAKE128` | `mcrypto.hashes.xof.xof` | `SHAKE128` | [Use and example](../algorithms/by-name/xof.md#xof-shake128) | [Guide](../algorithms/by-name/xof.md) | `available` | — |
| <a id="xof-shake256"></a>`SHAKE256` | `mcrypto.hashes.xof.xof` | `SHAKE256` | [Use and example](../algorithms/by-name/xof.md#xof-shake256) | [Guide](../algorithms/by-name/xof.md) | `available` | — |
| <a id="xof-turboshake128"></a>`TurboSHAKE128` | `mcrypto.hashes.turboshake.turboshake`<br>`mcrypto.hashes.turboshake.TurboSHAKE` | `TurboSHAKE128` | [Use and example](../algorithms/by-name/xof.md#xof-turboshake128) | [Guide](../algorithms/by-name/xof.md) | `available` | — |
| <a id="xof-turboshake256"></a>`TurboSHAKE256` | `mcrypto.hashes.turboshake.turboshake`<br>`mcrypto.hashes.turboshake.TurboSHAKE` | `TurboSHAKE256` | [Use and example](../algorithms/by-name/xof.md#xof-turboshake256) | [Guide](../algorithms/by-name/xof.md) | `available` | — |

## Public-key encryption

| Algorithm | Public API/import | Selector or operation | Individual use and example | Family guide | Availability | Note |
|:--|:--|:--|:--|:--|:--|:--|
| <a id="public-key-encryption-rsa"></a>`RSA` | `mcrypto.public_key.encryption.generate_keypair`<br>`mcrypto.public_key.encryption.encrypt`<br>`mcrypto.public_key.encryption.decrypt` | `RSA`<br>`RSA/PKCS1-1.5`<br>`RSA/OAEP-MGF1(SHA-1)`<br>`RSA/OAEP-MGF1(SHA-256)` | [Use and example](../algorithms/by-name/public-key-encryption.md#public-key-encryption-rsa) | [Guide](../algorithms/by-name/public-key-encryption.md) | `available` | — |
| <a id="public-key-encryption-rabin"></a>`Rabin` | `mcrypto.public_key.encryption.generate_keypair`<br>`mcrypto.public_key.encryption.encrypt`<br>`mcrypto.public_key.encryption.decrypt` | `Rabin`<br>`Rabin/OAEP-MGF1(SHA-1)` | [Use and example](../algorithms/by-name/public-key-encryption.md#public-key-encryption-rabin) | [Guide](../algorithms/by-name/public-key-encryption.md) | `available` | — |
| <a id="public-key-encryption-rabin-williams"></a>`Rabin-Williams` | `mcrypto.public_key.encryption.generate_keypair`<br>`mcrypto.public_key.encryption.encrypt`<br>`mcrypto.public_key.encryption.decrypt` | `Rabin-Williams` | [Use and example](../algorithms/by-name/public-key-encryption.md#public-key-encryption-rabin-williams) | [Guide](../algorithms/by-name/public-key-encryption.md) | `available` | — |
| <a id="public-key-encryption-elgamal"></a>`ElGamal` | `mcrypto.public_key.encryption.generate_keypair`<br>`mcrypto.public_key.encryption.encrypt`<br>`mcrypto.public_key.encryption.decrypt` | `ElGamal` | [Use and example](../algorithms/by-name/public-key-encryption.md#public-key-encryption-elgamal) | [Guide](../algorithms/by-name/public-key-encryption.md) | `available` | — |
| <a id="public-key-encryption-luc"></a>`LUC` | `mcrypto.public_key.encryption.generate_keypair`<br>`mcrypto.public_key.encryption.encrypt`<br>`mcrypto.public_key.encryption.decrypt` | `LUC`<br>`LUC/OAEP-MGF1(SHA-1)` | [Use and example](../algorithms/by-name/public-key-encryption.md#public-key-encryption-luc) | [Guide](../algorithms/by-name/public-key-encryption.md) | `available` | — |
| <a id="public-key-encryption-lucelg"></a>`LUCELG` | `mcrypto.public_key.encryption.generate_keypair`<br>`mcrypto.public_key.encryption.encrypt`<br>`mcrypto.public_key.encryption.decrypt` | `LUCELG`<br>`LUC-IES(KDF2(SHA-1),XOR,HMAC(SHA-1))` | [Use and example](../algorithms/by-name/public-key-encryption.md#public-key-encryption-lucelg) | [Guide](../algorithms/by-name/public-key-encryption.md) | `available` | — |
| <a id="public-key-encryption-dlies"></a>`DLIES` | `mcrypto.public_key.encryption.generate_keypair`<br>`mcrypto.public_key.encryption.encrypt`<br>`mcrypto.public_key.encryption.decrypt` | `DLIES` | [Use and example](../algorithms/by-name/public-key-encryption.md#public-key-encryption-dlies) | [Guide](../algorithms/by-name/public-key-encryption.md) | `available` | — |
| <a id="public-key-encryption-ecies"></a>`ECIES` | `mcrypto.public_key.encryption.generate_keypair`<br>`mcrypto.public_key.encryption.encrypt`<br>`mcrypto.public_key.encryption.decrypt` | `ECIES`<br>`ECIES(P-256,SHA-256)` | [Use and example](../algorithms/by-name/public-key-encryption.md#public-key-encryption-ecies) | [Guide](../algorithms/by-name/public-key-encryption.md) | `available` | — |

## Signatures

| Algorithm | Public API/import | Selector or operation | Individual use and example | Family guide | Availability | Note |
|:--|:--|:--|:--|:--|:--|:--|
| <a id="signature-rsa"></a>`RSA` | `mcrypto.signatures.dispatch.generate_keypair`<br>`mcrypto.signatures.dispatch.sign`<br>`mcrypto.signatures.dispatch.verify` | `RSA`<br>`RSA/PSS-MGF1(SHA-1)`<br>`RSA/PSS-MGF1(SHA-256)`<br>`RSA/PKCS1-1.5(SHA-1)`<br>`RSA/PKCS1-1.5(SHA-256)` | [Use and example](../algorithms/by-name/signature.md#signature-rsa) | [Guide](../algorithms/by-name/signature.md) | `available` | — |
| <a id="signature-elgamal"></a>`ElGamal` | `mcrypto.signatures.dispatch.generate_keypair`<br>`mcrypto.signatures.dispatch.sign`<br>`mcrypto.signatures.dispatch.verify` | `ElGamal` | [Use and example](../algorithms/by-name/signature.md#signature-elgamal) | [Guide](../algorithms/by-name/signature.md) | `available` | — |
| <a id="signature-luc"></a>`LUC` | `mcrypto.signatures.dispatch.generate_keypair`<br>`mcrypto.signatures.dispatch.sign`<br>`mcrypto.signatures.dispatch.verify` | `LUC`<br>`LUC/PKCS1-1.5(SHA-256)`<br>`LUC-HMP/EMSA1(SHA-256)` | [Use and example](../algorithms/by-name/signature.md#signature-luc) | [Guide](../algorithms/by-name/signature.md) | `available` | — |
| <a id="signature-dsa"></a>`DSA` | `mcrypto.signatures.dispatch.generate_keypair`<br>`mcrypto.signatures.dispatch.sign`<br>`mcrypto.signatures.dispatch.verify` | `DSA` | [Use and example](../algorithms/by-name/signature.md#signature-dsa) | [Guide](../algorithms/by-name/signature.md) | `available` | — |
| <a id="signature-dsa-rfc6979"></a>`DSA-RFC6979` | `mcrypto.signatures.dispatch.generate_keypair`<br>`mcrypto.signatures.dispatch.sign`<br>`mcrypto.signatures.dispatch.verify` | `DSA-RFC6979` | [Use and example](../algorithms/by-name/signature.md#signature-dsa-rfc6979) | [Guide](../algorithms/by-name/signature.md) | `available` | — |
| <a id="signature-nr"></a>`NR` | `mcrypto.signatures.dispatch.generate_keypair`<br>`mcrypto.signatures.dispatch.sign`<br>`mcrypto.signatures.dispatch.verify` | `NR` | [Use and example](../algorithms/by-name/signature.md#signature-nr) | [Guide](../algorithms/by-name/signature.md) | `available` | — |
| <a id="signature-rabin-williams"></a>`Rabin-Williams` | `mcrypto.signatures.dispatch.generate_keypair`<br>`mcrypto.signatures.dispatch.sign`<br>`mcrypto.signatures.dispatch.verify` | `Rabin-Williams` | [Use and example](../algorithms/by-name/signature.md#signature-rabin-williams) | [Guide](../algorithms/by-name/signature.md) | `available` | — |
| <a id="signature-ecgdsa"></a>`ECGDSA` | `mcrypto.signatures.dispatch.generate_keypair`<br>`mcrypto.signatures.dispatch.sign`<br>`mcrypto.signatures.dispatch.verify` | `ECGDSA`<br>`ECGDSA(P-256,SHA-256)`<br>`ECGDSA(Brainpool-P256,SHA-256)` | [Use and example](../algorithms/by-name/signature.md#signature-ecgdsa) | [Guide](../algorithms/by-name/signature.md) | `available` | — |
| <a id="signature-esign"></a>`ESIGN` | `mcrypto.signatures.dispatch.generate_keypair`<br>`mcrypto.signatures.dispatch.sign`<br>`mcrypto.signatures.dispatch.verify` | `ESIGN` | [Use and example](../algorithms/by-name/signature.md#signature-esign) | [Guide](../algorithms/by-name/signature.md) | `available` | — |
| <a id="signature-ecdsa"></a>`ECDSA` | `mcrypto.signatures.dispatch.generate_keypair`<br>`mcrypto.signatures.dispatch.sign`<br>`mcrypto.signatures.dispatch.verify` | `ECDSA`<br>`ECDSA(P-256,SHA-256)` | [Use and example](../algorithms/by-name/signature.md#signature-ecdsa) | [Guide](../algorithms/by-name/signature.md) | `available` | — |
| <a id="signature-ecdsa-rfc6979"></a>`ECDSA-RFC6979` | `mcrypto.signatures.dispatch.generate_keypair`<br>`mcrypto.signatures.dispatch.sign`<br>`mcrypto.signatures.dispatch.verify` | `ECDSA-RFC6979`<br>`ECDSA-RFC6979(P-256,SHA-256)` | [Use and example](../algorithms/by-name/signature.md#signature-ecdsa-rfc6979) | [Guide](../algorithms/by-name/signature.md) | `available` | — |
| <a id="signature-ed25519"></a>`Ed25519` | `mcrypto.signatures.dispatch.generate_keypair`<br>`mcrypto.signatures.dispatch.sign`<br>`mcrypto.signatures.dispatch.verify`<br>`mcrypto.signatures.ed25519.keypair`<br>`mcrypto.signatures.ed25519.sign`<br>`mcrypto.signatures.ed25519.verify` | `Ed25519` | [Use and example](../algorithms/by-name/signature.md#signature-ed25519) | [Guide](../algorithms/by-name/signature.md) | `available` | — |
| <a id="signature-ecnr"></a>`ECNR` | `mcrypto.signatures.dispatch.generate_keypair`<br>`mcrypto.signatures.dispatch.sign`<br>`mcrypto.signatures.dispatch.verify` | `ECNR`<br>`ECNR(P-256,SHA-256)` | [Use and example](../algorithms/by-name/signature.md#signature-ecnr) | [Guide](../algorithms/by-name/signature.md) | `available` | — |
| <a id="signature-ed25519ph"></a>`Ed25519ph` | `mcrypto.signatures.ed25519.sign_ph`<br>`mcrypto.signatures.ed25519.verify_ph` | `sign_ph`<br>`verify_ph` | [Use and example](../algorithms/by-name/signature.md#signature-ed25519ph) | [Guide](../algorithms/by-name/signature.md) | `available` | Use the direct sign_ph and verify_ph functions. |

## Schemes and encodings

| Algorithm | Public API/import | Selector or operation | Individual use and example | Family guide | Availability | Note |
|:--|:--|:--|:--|:--|:--|:--|
| <a id="scheme-pkcs1-v1-5"></a>`PKCS1-v1.5` | `mcrypto.public_key.encryption.encrypt`<br>`mcrypto.public_key.encryption.decrypt`<br>`mcrypto.signatures.dispatch.sign`<br>`mcrypto.signatures.dispatch.verify` | `PKCS1-v1.5` | [Use and example](../algorithms/by-name/scheme.md#scheme-pkcs1-v1-5) | [Guide](../algorithms/by-name/scheme.md) | `composed` | select it through a complete encryption or signature scheme because there is no standalone padding dispatcher. |
| <a id="scheme-pkcs1-v2-0"></a>`PKCS1-v2.0` | `mcrypto.public_key.encryption.encrypt`<br>`mcrypto.public_key.encryption.decrypt`<br>`mcrypto.signatures.dispatch.sign`<br>`mcrypto.signatures.dispatch.verify` | `PKCS1-v2.0` | [Use and example](../algorithms/by-name/scheme.md#scheme-pkcs1-v2-0) | [Guide](../algorithms/by-name/scheme.md) | `composed` | select it through a complete encryption or signature scheme because there is no standalone padding dispatcher. |
| <a id="scheme-oaep"></a>`OAEP` | `mcrypto.public_key.encryption.encrypt`<br>`mcrypto.public_key.encryption.decrypt` | `Rabin/OAEP-MGF1(SHA-1)` | [Use and example](../algorithms/by-name/scheme.md#scheme-oaep) | [Guide](../algorithms/by-name/scheme.md) | `composed` | select it through a complete encryption or signature scheme because there is no standalone padding dispatcher. |
| <a id="scheme-pss"></a>`PSS` | `mcrypto.signatures.dispatch.sign`<br>`mcrypto.signatures.dispatch.verify` | `PSS` | [Use and example](../algorithms/by-name/scheme.md#scheme-pss) | [Guide](../algorithms/by-name/scheme.md) | `composed` | select it through a complete encryption or signature scheme because there is no standalone padding dispatcher. |
| <a id="scheme-pssr"></a>`PSSR` | `mcrypto.signatures.dispatch.sign`<br>`mcrypto.signatures.dispatch.verify` | `Rabin/PSSR(SHA-256)` | [Use and example](../algorithms/by-name/scheme.md#scheme-pssr) | [Guide](../algorithms/by-name/scheme.md) | `composed` | select it through a complete encryption or signature scheme because there is no standalone padding dispatcher. |
| <a id="scheme-ieee-p1363-emsa2"></a>`IEEE-P1363-EMSA2` | `mcrypto.signatures.dispatch.sign`<br>`mcrypto.signatures.dispatch.verify` | `Rabin-Williams/IEEE-P1363-EMSA2(SHA-256)` | [Use and example](../algorithms/by-name/scheme.md#scheme-ieee-p1363-emsa2) | [Guide](../algorithms/by-name/scheme.md) | `composed` | select it through a complete encryption or signature scheme because there is no standalone padding dispatcher. |
| <a id="scheme-ieee-p1363-emsa5"></a>`IEEE-P1363-EMSA5` | `mcrypto.signatures.dispatch.sign`<br>`mcrypto.signatures.dispatch.verify` | `IEEE-P1363-EMSA5` | [Use and example](../algorithms/by-name/scheme.md#scheme-ieee-p1363-emsa5) | [Guide](../algorithms/by-name/scheme.md) | `composed` | select it through a complete encryption or signature scheme because there is no standalone padding dispatcher. |

## Key agreement

| Algorithm | Public API/import | Selector or operation | Individual use and example | Family guide | Availability | Note |
|:--|:--|:--|:--|:--|:--|:--|
| <a id="key-agreement-dh"></a>`DH` | `mcrypto.key_exchange.agreement.generate_keypair`<br>`mcrypto.key_exchange.agreement.agree` | `DH` | [Use and example](../algorithms/by-name/key-agreement.md#key-agreement-dh) | [Guide](../algorithms/by-name/key-agreement.md) | `available` | — |
| <a id="key-agreement-dh2"></a>`DH2` | `mcrypto.key_exchange.agreement.generate_keypair`<br>`mcrypto.key_exchange.agreement.agree` | `DH2` | [Use and example](../algorithms/by-name/key-agreement.md#key-agreement-dh2) | [Guide](../algorithms/by-name/key-agreement.md) | `available` | — |
| <a id="key-agreement-mqv"></a>`MQV` | `mcrypto.key_exchange.agreement.generate_keypair`<br>`mcrypto.key_exchange.agreement.agree` | `MQV`<br>`ECMQV-P256`<br>`ECHMQV-P256`<br>`ECFHMQV-P256` | [Use and example](../algorithms/by-name/key-agreement.md#key-agreement-mqv) | [Guide](../algorithms/by-name/key-agreement.md) | `available` | — |
| <a id="key-agreement-hmqv"></a>`HMQV` | `mcrypto.key_exchange.agreement.generate_keypair`<br>`mcrypto.key_exchange.agreement.agree` | `HMQV` | [Use and example](../algorithms/by-name/key-agreement.md#key-agreement-hmqv) | [Guide](../algorithms/by-name/key-agreement.md) | `available` | — |
| <a id="key-agreement-fhmqv"></a>`FHMQV` | `mcrypto.key_exchange.agreement.generate_keypair`<br>`mcrypto.key_exchange.agreement.agree` | `FHMQV` | [Use and example](../algorithms/by-name/key-agreement.md#key-agreement-fhmqv) | [Guide](../algorithms/by-name/key-agreement.md) | `available` | — |
| <a id="key-agreement-lucdif"></a>`LUCDIF` | `mcrypto.key_exchange.agreement.generate_keypair`<br>`mcrypto.key_exchange.agreement.agree` | `LUCDIF` | [Use and example](../algorithms/by-name/key-agreement.md#key-agreement-lucdif) | [Guide](../algorithms/by-name/key-agreement.md) | `available` | — |
| <a id="key-agreement-xtr-dh"></a>`XTR-DH` | `mcrypto.key_exchange.agreement.generate_keypair`<br>`mcrypto.key_exchange.agreement.agree` | `XTR-DH` | [Use and example](../algorithms/by-name/key-agreement.md#key-agreement-xtr-dh) | [Guide](../algorithms/by-name/key-agreement.md) | `available` | — |
| <a id="key-agreement-ecdh"></a>`ECDH` | `mcrypto.key_exchange.agreement.generate_keypair`<br>`mcrypto.key_exchange.agreement.agree` | `ECDH-P256`<br>`ECDH` | [Use and example](../algorithms/by-name/key-agreement.md#key-agreement-ecdh) | [Guide](../algorithms/by-name/key-agreement.md) | `available` | — |
| <a id="key-agreement-ecmqv"></a>`ECMQV` | `mcrypto.key_exchange.agreement.generate_keypair`<br>`mcrypto.key_exchange.agreement.agree` | `ECMQV` | [Use and example](../algorithms/by-name/key-agreement.md#key-agreement-ecmqv) | [Guide](../algorithms/by-name/key-agreement.md) | `available` | — |
| <a id="key-agreement-echmqv"></a>`ECHMQV` | `mcrypto.key_exchange.agreement.generate_keypair`<br>`mcrypto.key_exchange.agreement.agree` | `ECHMQV` | [Use and example](../algorithms/by-name/key-agreement.md#key-agreement-echmqv) | [Guide](../algorithms/by-name/key-agreement.md) | `available` | — |
| <a id="key-agreement-ecfhmqv"></a>`ECFHMQV` | `mcrypto.key_exchange.agreement.generate_keypair`<br>`mcrypto.key_exchange.agreement.agree` | `ECFHMQV` | [Use and example](../algorithms/by-name/key-agreement.md#key-agreement-ecfhmqv) | [Guide](../algorithms/by-name/key-agreement.md) | `available` | — |
| <a id="key-agreement-x25519"></a>`X25519` | `mcrypto.key_exchange.agreement.generate_keypair`<br>`mcrypto.key_exchange.agreement.agree` | `X25519` | [Use and example](../algorithms/by-name/key-agreement.md#key-agreement-x25519) | [Guide](../algorithms/by-name/key-agreement.md) | `available` | — |

## KDFs

| Algorithm | Public API/import | Selector or operation | Individual use and example | Family guide | Availability | Note |
|:--|:--|:--|:--|:--|:--|:--|
| <a id="kdf-pbkdf1"></a>`PBKDF1` | `mcrypto.kdf.dispatch.derive` | `PBKDF1` | [Use and example](../algorithms/by-name/kdf.md#kdf-pbkdf1) | [Guide](../algorithms/by-name/kdf.md) | `available` | — |
| <a id="kdf-pbkdf2"></a>`PBKDF2` | `mcrypto.kdf.dispatch.derive` | `PBKDF2`<br>`PBKDF2-HMAC-SHA256`<br>`PBKDF2-HMAC-SHA1`<br>`PBKDF2-HMAC-SHA512` | [Use and example](../algorithms/by-name/kdf.md#kdf-pbkdf2) | [Guide](../algorithms/by-name/kdf.md) | `available` | — |
| <a id="kdf-pkcs12-pbkdf"></a>`PKCS12-PBKDF` | `mcrypto.kdf.dispatch.derive` | `PKCS12-PBKDF`<br>`PKCS12-PBKDF-SHA1` | [Use and example](../algorithms/by-name/kdf.md#kdf-pkcs12-pbkdf) | [Guide](../algorithms/by-name/kdf.md) | `available` | — |
| <a id="kdf-hkdf"></a>`HKDF` | `mcrypto.kdf.hkdf.derive` | `HKDF` | [Use and example](../algorithms/by-name/kdf.md#kdf-hkdf) | [Guide](../algorithms/by-name/kdf.md) | `composed` | Parameterized HKDF API; pass a specific accepted hash selector. |
| <a id="kdf-scrypt"></a>`Scrypt` | `mcrypto.kdf.dispatch.derive` | `Scrypt`<br>`scrypt` | [Use and example](../algorithms/by-name/kdf.md#kdf-scrypt) | [Guide](../algorithms/by-name/kdf.md) | `available` | — |
| <a id="kdf-blake2b-kdf"></a>`BLAKE2b-KDF` | `mcrypto.kdf.blake2b.derive` | `BLAKE2b-KDF` | [Use and example](../algorithms/by-name/kdf.md#kdf-blake2b-kdf) | [Guide](../algorithms/by-name/kdf.md) | `available` | — |
| <a id="kdf-hkdf-sha256"></a>`HKDF-SHA256` | `mcrypto.kdf.dispatch.derive` | `HKDF(SHA-256)`<br>`HKDF-SHA256` | [Use and example](../algorithms/by-name/kdf.md#kdf-hkdf-sha256) | [Guide](../algorithms/by-name/kdf.md) | `available` | — |
| <a id="kdf-hkdf-sha512"></a>`HKDF-SHA512` | `mcrypto.kdf.dispatch.derive` | `HKDF(SHA-512)`<br>`HKDF-SHA512` | [Use and example](../algorithms/by-name/kdf.md#kdf-hkdf-sha512) | [Guide](../algorithms/by-name/kdf.md) | `available` | — |

## Random generation

| Algorithm | Public API/import | Selector or operation | Individual use and example | Family guide | Availability | Note |
|:--|:--|:--|:--|:--|:--|:--|
| <a id="random-ansi-x9-17"></a>`ANSI-X9.17` | `mcrypto.random.legacy.X917RNG` | `ANSI-X9.17`<br>`ANSI-X9.17-3DES` | [Use and example](../algorithms/by-name/random.md#random-ansi-x9-17) | [Guide](../algorithms/by-name/random.md) | `available` | — |
| <a id="random-randompool"></a>`RandomPool` | `mcrypto.random.legacy.RandomPool` | `RandomPool` | [Use and example](../algorithms/by-name/random.md#random-randompool) | [Guide](../algorithms/by-name/random.md) | `available` | — |
| <a id="random-nist-hash-drbg"></a>`NIST-Hash-DRBG` | `mcrypto.random.drbg.hash_drbg` | `hash_drbg` | [Use and example](../algorithms/by-name/random.md#random-nist-hash-drbg) | [Guide](../algorithms/by-name/random.md) | `composed` | Parameterized Hash-DRBG API; pass an explicit digest selector. |
| <a id="random-nist-hmac-drbg"></a>`NIST-HMAC-DRBG` | `mcrypto.random.drbg.hmac_drbg` | `hmac_drbg` | [Use and example](../algorithms/by-name/random.md#random-nist-hmac-drbg) | [Guide](../algorithms/by-name/random.md) | `composed` | Parameterized HMAC-DRBG API; pass an explicit digest selector. |
| <a id="random-rdrand"></a>`RDRAND` | `mcrypto.random.legacy.hardware_random` | `RDRAND` | [Use and example](../algorithms/by-name/random.md#random-rdrand) | [Guide](../algorithms/by-name/random.md) | `available` | — |
| <a id="random-rdseed"></a>`RDSEED` | `mcrypto.random.legacy.hardware_random` | `RDSEED` | [Use and example](../algorithms/by-name/random.md#random-rdseed) | [Guide](../algorithms/by-name/random.md) | `available` | — |

## Secret sharing

| Algorithm | Public API/import | Selector or operation | Individual use and example | Family guide | Availability | Note |
|:--|:--|:--|:--|:--|:--|:--|
| <a id="secret-sharing-shamir-secret-sharing"></a>`Shamir-secret-sharing` | `mcrypto.utilities.secret_sharing.shamir_split`<br>`mcrypto.utilities.secret_sharing.shamir_recover` | `shamir_split`<br>`shamir_recover` | [Use and example](../algorithms/by-name/secret-sharing.md#secret-sharing-shamir-secret-sharing) | [Guide](../algorithms/by-name/secret-sharing.md) | `available` | — |
| <a id="secret-sharing-rabin-ida"></a>`Rabin-IDA` | `mcrypto.utilities.secret_sharing.ida_split`<br>`mcrypto.utilities.secret_sharing.ida_recover` | `ida_split`<br>`ida_recover` | [Use and example](../algorithms/by-name/secret-sharing.md#secret-sharing-rabin-ida) | [Guide](../algorithms/by-name/secret-sharing.md) | `available` | — |

## Finite fields and primes

| Algorithm | Public API/import | Selector or operation | Individual use and example | Family guide | Availability | Note |
|:--|:--|:--|:--|:--|:--|:--|
| <a id="math-gf-p"></a>`GF(p)` | `mcrypto.math.fields.PrimeField64`<br>`mcrypto.math.biguint.BigUInt` | `PrimeField64`<br>`BigUInt` | [Use and example](../algorithms/by-name/math.md#math-gf-p) | [Guide](../algorithms/by-name/math.md) | `available` | — |
| <a id="math-gf-2n"></a>`GF(2^n)` | `mcrypto.math.fields.GF256`<br>`mcrypto.math.fields.GF2_32` | `GF256`<br>`GF2_32` | [Use and example](../algorithms/by-name/math.md#math-gf-2n) | [Guide](../algorithms/by-name/math.md) | `available` | — |
| <a id="math-prime-generation"></a>`Prime generation` | `mcrypto.math.primes.is_probable_prime`<br>`mcrypto.math.primes.generate_probable_prime`<br>`mcrypto.math.primes.generate_provable_prime` | `is_probable_prime`<br>`generate_probable_prime`<br>`generate_provable_prime` | [Use and example](../algorithms/by-name/math.md#math-prime-generation) | [Guide](../algorithms/by-name/math.md) | `available` | — |

## Compression

| Algorithm | Public API/import | Selector or operation | Individual use and example | Family guide | Availability | Note |
|:--|:--|:--|:--|:--|:--|:--|
| <a id="compression-deflate"></a>`DEFLATE` | `mcrypto.compression.transforms.transform` | `Deflate`<br>`Inflate` | [Use and example](../algorithms/by-name/compression.md#compression-deflate) | [Guide](../algorithms/by-name/compression.md) | `available` | — |
| <a id="compression-gzip"></a>`gzip` | `mcrypto.compression.transforms.transform` | `Gzip`<br>`Gunzip` | [Use and example](../algorithms/by-name/compression.md#compression-gzip) | [Guide](../algorithms/by-name/compression.md) | `available` | — |
| <a id="compression-zlib"></a>`zlib` | `mcrypto.compression.transforms.transform` | `ZlibCompress`<br>`ZlibDecompress` | [Use and example](../algorithms/by-name/compression.md#compression-zlib) | [Guide](../algorithms/by-name/compression.md) | `available` | — |

## Binary-to-text encoding

| Algorithm | Public API/import | Selector or operation | Individual use and example | Family guide | Availability | Note |
|:--|:--|:--|:--|:--|:--|:--|
| <a id="encoding-hex"></a>`Hex` | `mcrypto.encoding.transforms.transform` | `HexEncode`<br>`HexDecode` | [Use and example](../algorithms/by-name/encoding.md#encoding-hex) | [Guide](../algorithms/by-name/encoding.md) | `available` | — |
| <a id="encoding-base32"></a>`Base32` | `mcrypto.encoding.transforms.transform` | `Base32Encode`<br>`Base32Decode` | [Use and example](../algorithms/by-name/encoding.md#encoding-base32) | [Guide](../algorithms/by-name/encoding.md) | `available` | — |
| <a id="encoding-base64"></a>`Base64` | `mcrypto.encoding.transforms.transform` | `Base64Encode`<br>`Base64Decode` | [Use and example](../algorithms/by-name/encoding.md#encoding-base64) | [Guide](../algorithms/by-name/encoding.md) | `available` | — |
| <a id="encoding-base64url"></a>`Base64URL` | `mcrypto.encoding.transforms.transform` | `Base64URLEncode`<br>`Base64URLDecode` | [Use and example](../algorithms/by-name/encoding.md#encoding-base64url) | [Guide](../algorithms/by-name/encoding.md) | `available` | — |

## Authenticated boxes

| Algorithm | Public API/import | Selector or operation | Individual use and example | Family guide | Availability | Note |
|:--|:--|:--|:--|:--|:--|:--|
| <a id="box-curve25519-xsalsa20-poly1305"></a>`Curve25519-XSalsa20-Poly1305` | `mcrypto.public_key.box.keypair`<br>`mcrypto.public_key.box.encrypt`<br>`mcrypto.public_key.box.decrypt` | `Curve25519-XSalsa20-Poly1305` | [Use and example](../algorithms/by-name/box.md#box-curve25519-xsalsa20-poly1305) | [Guide](../algorithms/by-name/box.md) | `available` | — |
| <a id="box-curve25519-xchacha20-poly1305"></a>`Curve25519-XChaCha20-Poly1305` | `mcrypto.public_key.box_variants.xchacha20poly1305_encrypt_easy`<br>`mcrypto.public_key.box_variants.xchacha20poly1305_decrypt_easy` | `xchacha20poly1305_encrypt_easy`<br>`xchacha20poly1305_decrypt_easy` | [Use and example](../algorithms/by-name/box.md#box-curve25519-xchacha20-poly1305) | [Guide](../algorithms/by-name/box.md) | `available` | — |
| <a id="box-sealed-box"></a>`sealed-box` | `mcrypto.public_key.box_variants.seal`<br>`mcrypto.public_key.box_variants.seal_open` | `seal`<br>`seal_open` | [Use and example](../algorithms/by-name/box.md#box-sealed-box) | [Guide](../algorithms/by-name/box.md) | `available` | — |

## Groups and scalar multiplication

| Algorithm | Public API/import | Selector or operation | Individual use and example | Family guide | Availability | Note |
|:--|:--|:--|:--|:--|:--|:--|
| <a id="group-ed25519"></a>`Ed25519` | `mcrypto.groups.scalar.scalar_mult`<br>`mcrypto.groups.scalar.scalar_base` | `scalar_mult`<br>`scalar_base`<br>`Ed25519` | [Use and example](../algorithms/by-name/group.md#group-ed25519) | [Guide](../algorithms/by-name/group.md) | `available` | — |
| <a id="group-ristretto255"></a>`Ristretto255` | `mcrypto.groups.scalar.scalar_mult`<br>`mcrypto.groups.scalar.scalar_base` | `core`<br>`scalar-mul`<br>`scalar-reduce`<br>`from-hash`<br>`scalar-invert`<br>`is-valid`<br>`point-add`<br>`add`<br>`point-sub`<br>`sub`<br>`scalar-negate`<br>`scalar-complement`<br>`scalar-add`<br>`Ristretto255` | [Use and example](../algorithms/by-name/group.md#group-ristretto255) | [Guide](../algorithms/by-name/group.md) | `available` | — |
| <a id="group-x25519"></a>`X25519` | `mcrypto.groups.scalar.scalar_mult`<br>`mcrypto.groups.scalar.scalar_base` | `X25519` | [Use and example](../algorithms/by-name/group.md#group-x25519) | [Guide](../algorithms/by-name/group.md) | `available` | — |

## Core permutations

| Algorithm | Public API/import | Selector or operation | Individual use and example | Family guide | Availability | Note |
|:--|:--|:--|:--|:--|:--|:--|
| <a id="core-hchacha20"></a>`HChaCha20` | `mcrypto.groups.scalar.core_operation` | `HChaCha20` | [Use and example](../algorithms/by-name/core.md#core-hchacha20) | [Guide](../algorithms/by-name/core.md) | `available` | — |
| <a id="core-hsalsa20"></a>`HSalsa20` | `mcrypto.groups.scalar.core_operation` | `HSalsa20` | [Use and example](../algorithms/by-name/core.md#core-hsalsa20) | [Guide](../algorithms/by-name/core.md) | `available` | — |
| <a id="core-keccak-f1600"></a>`Keccak-f1600` | `mcrypto.groups.scalar.core_operation` | `Keccak-f1600` | [Use and example](../algorithms/by-name/core.md#core-keccak-f1600) | [Guide](../algorithms/by-name/core.md) | `available` | — |
| <a id="core-salsa20"></a>`Salsa20` | `mcrypto.groups.scalar.core_operation` | `Salsa20` | [Use and example](../algorithms/by-name/core.md#core-salsa20) | [Guide](../algorithms/by-name/core.md) | `available` | — |
| <a id="core-salsa20-12"></a>`Salsa20-12` | `mcrypto.groups.scalar.core_operation` | `Salsa20-12` | [Use and example](../algorithms/by-name/core.md#core-salsa20-12) | [Guide](../algorithms/by-name/core.md) | `available` | — |
| <a id="core-salsa20-8"></a>`Salsa20-8` | `mcrypto.groups.scalar.core_operation` | `Salsa20-8` | [Use and example](../algorithms/by-name/core.md#core-salsa20-8) | [Guide](../algorithms/by-name/core.md) | `available` | — |

## KEMs

| Algorithm | Public API/import | Selector or operation | Individual use and example | Family guide | Availability | Note |
|:--|:--|:--|:--|:--|:--|:--|
| <a id="kem-ml-kem-768"></a>`ML-KEM-768` | `mcrypto.kem.dispatch.keypair`<br>`mcrypto.kem.dispatch.encapsulate`<br>`mcrypto.kem.dispatch.decapsulate` | `ML-KEM-768` | [Use and example](../algorithms/by-name/kem.md#kem-ml-kem-768) | [Guide](../algorithms/by-name/kem.md) | `available` | — |
| <a id="kem-x-wing"></a>`X-Wing` | `mcrypto.kem.dispatch.keypair`<br>`mcrypto.kem.dispatch.encapsulate`<br>`mcrypto.kem.dispatch.decapsulate` | `X-Wing` | [Use and example](../algorithms/by-name/kem.md#kem-x-wing) | [Guide](../algorithms/by-name/kem.md) | `available` | — |

## Key exchange

| Algorithm | Public API/import | Selector or operation | Individual use and example | Family guide | Availability | Note |
|:--|:--|:--|:--|:--|:--|:--|
| <a id="key-exchange-x25519-blake2b"></a>`X25519-BLAKE2b` | `mcrypto.key_exchange.kx.keypair`<br>`mcrypto.key_exchange.kx.session_keys` | `keypair`<br>`session_keys` | [Use and example](../algorithms/by-name/key-exchange.md#key-exchange-x25519-blake2b) | [Guide](../algorithms/by-name/key-exchange.md) | `available` | — |

## IP address encryption

| Algorithm | Public API/import | Selector or operation | Individual use and example | Family guide | Availability | Note |
|:--|:--|:--|:--|:--|:--|:--|
| <a id="ipcrypt-ipcrypt"></a>`IPcrypt` | `mcrypto.ipcrypt.dispatch.ipcrypt` | `IPcrypt` | [Use and example](../algorithms/by-name/ipcrypt.md#ipcrypt-ipcrypt) | [Guide](../algorithms/by-name/ipcrypt.md) | `available` | — |
| <a id="ipcrypt-ipcrypt-nd"></a>`IPcrypt-ND` | `mcrypto.ipcrypt.dispatch.ipcrypt` | `IPcrypt-ND` | [Use and example](../algorithms/by-name/ipcrypt.md#ipcrypt-ipcrypt-nd) | [Guide](../algorithms/by-name/ipcrypt.md) | `available` | — |
| <a id="ipcrypt-ipcrypt-ndx"></a>`IPcrypt-NDX` | `mcrypto.ipcrypt.dispatch.ipcrypt` | `IPcrypt-NDX` | [Use and example](../algorithms/by-name/ipcrypt.md#ipcrypt-ipcrypt-ndx) | [Guide](../algorithms/by-name/ipcrypt.md) | `available` | — |
| <a id="ipcrypt-ipcrypt-pfx"></a>`IPcrypt-PFX` | `mcrypto.ipcrypt.dispatch.ipcrypt` | `IPcrypt-PFX` | [Use and example](../algorithms/by-name/ipcrypt.md#ipcrypt-ipcrypt-pfx) | [Guide](../algorithms/by-name/ipcrypt.md) | `available` | — |

## Password hashing

| Algorithm | Public API/import | Selector or operation | Individual use and example | Family guide | Availability | Note |
|:--|:--|:--|:--|:--|:--|:--|
| <a id="password-hash-argon2i"></a>`Argon2i` | `mcrypto.kdf.argon2.argon2i` | `Argon2i` | [Use and example](../algorithms/by-name/password-hash.md#password-hash-argon2i) | [Guide](../algorithms/by-name/password-hash.md) | `available` | — |
| <a id="password-hash-argon2id"></a>`Argon2id` | `mcrypto.passwords.argon2id.derive` | `Argon2id` | [Use and example](../algorithms/by-name/password-hash.md#password-hash-argon2id) | [Guide](../algorithms/by-name/password-hash.md) | `available` | — |
| <a id="password-hash-scrypt-salsa20-8-sha256"></a>`Scrypt-Salsa20-8-SHA256` | `mcrypto.kdf.scrypt.scrypt` | `Scrypt-Salsa20-8-SHA256` | [Use and example](../algorithms/by-name/password-hash.md#password-hash-scrypt-salsa20-8-sha256) | [Guide](../algorithms/by-name/password-hash.md) | `available` | — |

## Secret boxes

| Algorithm | Public API/import | Selector or operation | Individual use and example | Family guide | Availability | Note |
|:--|:--|:--|:--|:--|:--|:--|
| <a id="secretbox-xsalsa20-poly1305"></a>`XSalsa20-Poly1305` | `mcrypto.secretbox.xsalsa20poly1305.encrypt`<br>`mcrypto.secretbox.xsalsa20poly1305.decrypt` | `XSalsa20-Poly1305` | [Use and example](../algorithms/by-name/secretbox.md#secretbox-xsalsa20-poly1305) | [Guide](../algorithms/by-name/secretbox.md) | `available` | — |
| <a id="secretbox-xchacha20-poly1305"></a>`XChaCha20-Poly1305` | `mcrypto.secretbox.xchacha20poly1305.encrypt`<br>`mcrypto.secretbox.xchacha20poly1305.decrypt` | `XChaCha20-Poly1305` | [Use and example](../algorithms/by-name/secretbox.md#secretbox-xchacha20-poly1305) | [Guide](../algorithms/by-name/secretbox.md) | `available` | — |

## Secret streams

| Algorithm | Public API/import | Selector or operation | Individual use and example | Family guide | Availability | Note |
|:--|:--|:--|:--|:--|:--|:--|
| <a id="secretstream-xchacha20-poly1305-secretstream"></a>`XChaCha20-Poly1305-secretstream` | `mcrypto.secretstream.xchacha20poly1305.PushStream`<br>`mcrypto.secretstream.xchacha20poly1305.PullStream` | `PushStream`<br>`PullStream` | [Use and example](../algorithms/by-name/secretstream.md#secretstream-xchacha20-poly1305-secretstream) | [Guide](../algorithms/by-name/secretstream.md) | `available` | — |

## Security utilities

| Algorithm | Public API/import | Selector or operation | Individual use and example | Family guide | Availability | Note |
|:--|:--|:--|:--|:--|:--|:--|
| <a id="utility-constant-time-verify"></a>`constant-time-verify` | `mcrypto.traits.constant_time_equal` | `constant_time_equal` | [Use and example](../algorithms/by-name/utility.md#utility-constant-time-verify) | [Guide](../algorithms/by-name/utility.md) | `available` | — |
| <a id="utility-secure-memory"></a>`secure-memory` | `mcrypto.secure_memory.LockedSecretBytes`<br>`mcrypto.secure_memory.page_locking_available` | `LockedSecretBytes`<br>`page_locking_available` | [Use and example](../algorithms/by-name/utility.md#utility-secure-memory) | [Guide](../algorithms/by-name/utility.md) | `available` | — |
| <a id="utility-system-csprng"></a>`system-CSPRNG` | `mcrypto.random.generator.random_bytes` | `random_bytes` | [Use and example](../algorithms/by-name/utility.md#utility-system-csprng) | [Guide](../algorithms/by-name/utility.md) | `available` | — |
