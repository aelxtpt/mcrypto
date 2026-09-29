# Contributing

## Set up a checkout

Use the source checkout and Pixi environments:

```sh
git clone https://github.com/aelxtpt/mcrypto.git
cd mcrypto
pixi install
pixi install -e docs
```

Do not update dependency pins as an incidental part of another change.

## Develop and verify

Run the narrowest existing test that exercises the changed behavior while developing. Before submitting a change, run the maintained full checks:

```sh
pixi run test-coverage
pixi run test
pixi run format
```

Target-specific changes may require additional native checks. Do not mark deferred, skipped, unavailable, or inconclusive checks as a pass.

Every new public behavior must include an observable behavioral test and the corresponding executed-evidence mapping in `tests/coverage_registry`. Tests must check outputs, errors, state transitions, boundaries, or other caller-observable contracts rather than source text or symbol presence.

## Security reports

Do not disclose a suspected vulnerability in an issue or pull request. Follow `SECURITY.md` and create a private draft security advisory through GitHub Security.

## License

By submitting a contribution, you agree that it is licensed under the repository's MIT License.
