//! Functions for validating the base58 hash checksums, including specifically
//! the bitcoin and litecoin addresses.

extern crate num;
extern crate sha2;

use num::bigint::{ToBigUint,BigUint};
use num::traits::ToPrimitive;
use num::Zero;
use sha2::{Sha256, Digest};

#[derive(PartialEq, Debug)]
pub enum ValidationError {
    /// Given address is too short to be valid
    TooShort,
    /// Encoding is not a valid base58
    InvalidEncoding,
    /// Computed hash does not match the embedded one
    HashMismatch,

    // currency specific
    /// This address is not a bitcoin address (testnet or real).
    /// May happen when attempting to validate btc address
    NotBitcoin,
    /// This address is not a litecoin address.
    /// May happen when attempting to validate ltc address
    NotLitecoin,
}

static BASE58_CHARS: &'static str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

fn decode_base58(bc: &str) -> Option<BigUint> {
    let mut res: BigUint = Zero::zero();
    let b58: BigUint = 58.to_biguint().unwrap();

    for c in bc.chars() {
        match BASE58_CHARS.find(c) {
            None => {
                return None
            },
            Some(x) => {
                res = res * &b58 + x.to_biguint().unwrap();
            }
        }
    }
    Some(res)
}

fn biguint_to_bytes(n: BigUint) -> Vec<u8> {
    let mut res: Vec<u8> = Vec::new();
    let mut tmp = n;
    let b256: BigUint = 256.to_biguint().unwrap();

    while !tmp.is_zero() {
        res.insert(0, (&tmp % &b256).to_u8().unwrap());
        tmp = tmp / &b256;
    }

    if res.len() == 0 {
        return vec!(0);
    }

    res
}

fn pad_to(v: Vec<u8>, len: usize) -> Vec<u8> {
    let mut tmp: Vec<u8> = v;
    while tmp.len() < len {
        tmp.insert(0, 0)
    }
    tmp
}

fn double_sha256(chunk: &[u8]) -> Vec<u8> {
    let mut hash = Sha256::default();
    hash.input(chunk);
    let mut hash2 = Sha256::default();
    hash2.input(&hash.result()[..]);
    hash2.result().into_iter().collect()
}

/// Validate provided generic base58 hash.
/// Returns the hash version/type if correct and an error otherwise.
pub fn validate_base58_hash(addr: &str) -> Result<usize, ValidationError> {
    if addr.len() == 0 {
        return Err(ValidationError::TooShort);
    }

    let big = match decode_base58(addr) {
        None => return Err(ValidationError::InvalidEncoding),
        Some(x) => x
    };
    let bytes = biguint_to_bytes(big);
    let padded = pad_to(bytes, 25);

    let hash = double_sha256(&padded[0 .. padded.len() - 4]);
    let short_hash = &hash[0..4];
    let known = &padded[padded.len()-4 .. padded.len()];
    if &short_hash[..] == known {
        Ok(padded[0] as usize)
    } else {
        Err(ValidationError::HashMismatch)
    }
}

/// Validate bitcoin address checksum.
/// Returns the hash version/type if correct and an error otherwise.
pub fn validate_btc_address(addr: &str) -> Result<usize, ValidationError> {
    match validate_base58_hash(addr) {
        Ok(0) => Ok(0),      // real address
        Ok(5) => Ok(5),      // script hash
        Ok(111) => Ok(111),  // testnet address
        Ok(_) => Err(ValidationError::NotBitcoin),
        Err(x) => Err(x)
    }
}

/// Validate litecoin address checksum.
/// Returns the hash version/type if correct and an error otherwise.
pub fn validate_ltc_address(addr: &str) -> Result<usize, ValidationError> {
    match validate_base58_hash(addr) {
        Ok(48) => Ok(48),      // real address
        Ok(111) => Ok(111),    // testnet address
        Ok(_) => Err(ValidationError::NotLitecoin),
        Err(x) => Err(x)
    }
}

