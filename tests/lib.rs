extern crate coinaddress;

use coinaddress::{validate_base58_hash,validate_btc_address,validate_ltc_address,ValidationError};


#[test]
fn test_validate_hash() {
    assert_eq!(validate_base58_hash("17VZNX1SN5NtKa8UQFxwQbFeFc3iqRYhem"), Ok(0));
    assert_eq!(validate_base58_hash("mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn"), Ok(111));
    assert_eq!(validate_base58_hash("17VZNX1SN5NtKa8UQFxwQbFeFc3iqRYheX"), Err(ValidationError::HashMismatch));
    assert_eq!(validate_base58_hash("17VZNX1SN5NtKa8UQFxwQbFeFc3iqRYh  "), Err(ValidationError::InvalidEncoding));
    assert_eq!(validate_base58_hash("1"), Err(ValidationError::HashMismatch));
    assert_eq!(validate_base58_hash(""), Err(ValidationError::TooShort));
}

#[test]
fn test_validate_btc_address() {
    assert_eq!(validate_btc_address("17VZNX1SN5NtKa8UQFxwQbFeFc3iqRYhem"), Ok(0));
    assert_eq!(validate_btc_address("3EktnHQD7RiAE6uzMj2ZifT9YgRrkSgzQX"), Ok(5));
    assert_eq!(validate_btc_address("mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn"), Ok(111));
    assert_eq!(validate_btc_address("LRELGDJyeCPRDXz4Dh1kWorMN9hTBB7CEz"), Err(ValidationError::NotBitcoin));
}

#[test]
fn test_validate_ltc_address() {
    assert_eq!(validate_ltc_address("LRELGDJyeCPRDXz4Dh1kWorMN9hTBB7CEz"), Ok(48));
    assert_eq!(validate_ltc_address("muen9zszN6rVwXaFw48xh6YkdUSjJcfzek"), Ok(111));
    assert_eq!(validate_ltc_address("17VZNX1SN5NtKa8UQFxwQbFeFc3iqRYhem"), Err(ValidationError::NotLitecoin));
}
