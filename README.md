Coinaddress
===========

Master: [![Master Build Status](https://travis-ci.org/viraptor/coinaddress.svg?branch=master)](https://travis-ci.org/viraptor/coinaddress)

Rust library for bitcoin / litecoin / generic base58 addresses checksum validation.
The actual check is validating the trailing checksum against the pubkey hash. All
addresses using the bitcoin format can be verified.

To validate bitcoin/litecoin address, check that:
```
validate_btc_address("1theaddress") == Ok(0)  // (or 5, or 111 for testnet)
validate_ltc_address("Ltheaddress") == Ok(48)
```

Any other address may be checked using:
```
validate_base58_hash("...") == Ok(...)
```

The value returned in `Ok(...)` is the address version/type.

To use the package add it to cargo dependencies:
```
[dependencies]
coinaddress = "1.*"
```
