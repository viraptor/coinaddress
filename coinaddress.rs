#![crate_type = "lib"]
#![crate_name = "coinaddress"]
#![license = "MIT"]

//! Functions for validating the base58 hash checksums, including specifically
//! the bitcoin and litecoin addresses.

extern crate num;
extern crate rustc;
extern crate test;

use num::bigint::BigUint;
use num::Zero;
use std::num::{from_uint, from_int};
use rustc::util::sha2::{Sha256, Digest};

#[deriving(PartialEq, Show)]
pub enum ValidationError {
    TooShort,
    InvalidEncoding,
    HashMismatch,

    // currency specific
    NotBitcoin,
    NotLitecoin,
}

static BASE58_CHARS: &'static str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

fn decode_base58(bc: &str) -> Option<BigUint> {
    let mut res: BigUint = Zero::zero();
    let b58: BigUint = from_int(58).unwrap();

    for c in bc.chars() {
        match BASE58_CHARS.find(c) {
            None => {
                return None
            },
            Some(x) => {
                res = res * b58 + from_uint(x).unwrap();
            }
        }
    }
    Some(res)
}

fn bigint_to_bytes(n: BigUint) -> Vec<u8> {
    let mut res: Vec<u8> = Vec::new();
    let mut tmp = n;
    let b256: BigUint = from_int(256).unwrap();

    while !tmp.is_zero() {
        res.insert(0, (tmp % b256).to_u8().unwrap());
        tmp = tmp / b256;
    }

    if res.len() == 0 {
        return vec!(0);
    }

    res
}

fn pad_to(v: Vec<u8>, len: uint) -> Vec<u8> {
    let mut tmp: Vec<u8> = v;
    while tmp.len() < len {
        tmp.insert(0, 0)
    }
    tmp
}

fn double_sha256(chunk: &[u8]) -> Vec<u8> {
    let mut hash = Sha256::new();
    hash.input(chunk);
    let mut hash2 = Sha256::new();
    hash2.input(hash.result_bytes().as_slice());
    hash2.result_bytes()
}

/// Validate provided generic base58 hash
/// Returning the hash version/type if correct and an error otherwise
pub fn validate_base58_hash(addr: &str) -> Result<uint, ValidationError> {
    if addr.len() == 0 {
        return Err(TooShort);
    }

    let big = match decode_base58(addr) {
        None => return Err(InvalidEncoding),
        Some(x) => x
    };
    let bytes = bigint_to_bytes(big);
    let padded = pad_to(bytes, 25);

    let hash = double_sha256(padded.slice(0, padded.len() - 4));
    let short_hash = hash.slice(0, 4);
    let known = padded.slice(padded.len()-4, padded.len());
    if short_hash.as_slice() == known {
        Ok(padded[0].to_uint().unwrap())
    } else {
        Err(HashMismatch)
    }
}

/// Validate bitcoin address checksum
/// Returning the hash version/type if correct and an error otherwise
pub fn validate_btc_address(addr: &str) -> Result<uint, ValidationError> {
    match validate_base58_hash(addr) {
        Ok(0) => Ok(0),      // real address
        Ok(5) => Ok(5),      // script hash
        Ok(111) => Ok(111),  // testnet address
        Ok(_) => Err(NotBitcoin),
        Err(x) => Err(x)
    }
}

/// Validate litecoin address checksum
/// Returning the hash version/type if correct and an error otherwise
pub fn validate_ltc_address(addr: &str) -> Result<uint, ValidationError> {
    match validate_base58_hash(addr) {
        Ok(48) => Ok(48),      // real address
        Ok(111) => Ok(111),    // testnet address
        Ok(_) => Err(NotLitecoin),
        Err(x) => Err(x)
    }
}

#[test]
fn test_decoding() {
    use std::num::from_str_radix;

    assert_eq!(decode_base58("1"), from_int(0));
    assert_eq!(decode_base58("1AaZz"), from_int(0x1C8485));
    assert_eq!(decode_base58("AO"), None);
    assert_eq!(decode_base58("1AGNa15ZQXAZUgFiqJ2i7Z2DPU2J6hW62i"), from_str_radix("65A16059864A2FDBC7C99A4723A8395BC6F188EBC046B2FF", 16));
}

#[test]
fn test_to_bytes() {
    assert_eq!(bigint_to_bytes(Zero::zero()), vec!(0));
    assert_eq!(bigint_to_bytes(from_int(1).unwrap()), vec!(1));
    assert_eq!(bigint_to_bytes(from_int(256).unwrap()), vec!(1, 0));
}

#[test]
fn test_validate_hash() {
    assert_eq!(validate_base58_hash("17VZNX1SN5NtKa8UQFxwQbFeFc3iqRYhem"), Ok(0));
    assert_eq!(validate_base58_hash("mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn"), Ok(111));
    assert_eq!(validate_base58_hash("17VZNX1SN5NtKa8UQFxwQbFeFc3iqRYheX"), Err(HashMismatch));
    assert_eq!(validate_base58_hash("17VZNX1SN5NtKa8UQFxwQbFeFc3iqRYh  "), Err(InvalidEncoding));
    assert_eq!(validate_base58_hash("1"), Err(HashMismatch));
    assert_eq!(validate_base58_hash(""), Err(TooShort));
}

#[test]
fn test_validate_btc_address() {
    assert_eq!(validate_btc_address("17VZNX1SN5NtKa8UQFxwQbFeFc3iqRYhem"), Ok(0));
    assert_eq!(validate_btc_address("3EktnHQD7RiAE6uzMj2ZifT9YgRrkSgzQX"), Ok(5));
    assert_eq!(validate_btc_address("mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn"), Ok(111));
    assert_eq!(validate_btc_address("LRELGDJyeCPRDXz4Dh1kWorMN9hTBB7CEz"), Err(NotBitcoin));
}

#[test]
fn test_validate_ltc_address() {
    assert_eq!(validate_ltc_address("LRELGDJyeCPRDXz4Dh1kWorMN9hTBB7CEz"), Ok(48));
    assert_eq!(validate_ltc_address("muen9zszN6rVwXaFw48xh6YkdUSjJcfzek"), Ok(111));
    assert_eq!(validate_ltc_address("17VZNX1SN5NtKa8UQFxwQbFeFc3iqRYhem"), Err(NotLitecoin));
}

#[bench]
fn bench_validate_hash(b: &mut test::Bencher) {
    b.iter(|| {
        validate_base58_hash("17VZNX1SN5NtKa8UQFxwQbFeFc3iqRYhem")
    })
}
