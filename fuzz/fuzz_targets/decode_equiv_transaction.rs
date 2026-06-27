// SPDX-License-Identifier: MIT OR Apache-2.0

//! Fuzz test for equivalent decoding between the legacy and consensus-encoding decoding schemes.

#![cfg_attr(fuzzing, no_main)]
#![cfg_attr(not(fuzzing), allow(unused))]
use libfuzzer_sys::fuzz_target;

use elements::bitcoin::hex::DisplayHex as _;

type Target = elements::Transaction;

#[cfg(not(fuzzing))]
fn main() {}

struct DisplayError<'e>(&'e dyn std::error::Error);

impl core::fmt::Display for DisplayError<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{}", self.0)?;
        let mut e = self.0;
        while let Some(source) = e.source() {
            writeln!(f, "caused by {}", source)?;
            e = source;
        }
        Ok(())
    }
}

fn do_test(data: &[u8]) {
    let old: Result<Target, _> = elements::encode::deserialize(data);
    let new: Result<Target, _> = elements::encoding::decode_from_slice(data);

    match (old, new) {
        (Err(_), Err(_)) => {},
        (Err(e), Ok(new)) => {
            let e = DisplayError(&e);
            panic!("Decodable trait failed with {e}; Decode parsed {:?}", new);
        }
        (Ok(old), Err(e)) => {
            let e = DisplayError(&e);
            panic!("Decode trait failed with {e}; Decodable parsed {:?}", old);
        }
        (Ok(old), Ok(new)) => {
            assert_eq!(
                old, new,
                "Decodable (left) did not match Decode (right)",
            );

            let reser_old = elements::encode::serialize(&old);
            let reser_new = elements::encoding::encode_to_vec(&new);
            assert_eq!(
                reser_old, reser_new,
                "Encodable (left) did not match Encode (right)\nOld hex: {}\nNew hex: {}\nTransaction: {:?}",
                reser_old.as_hex(),
                reser_new.as_hex(),
                old,
            );
        }
    }
}

fuzz_target!(|data: &[u8]| {
    do_test(data);
});

#[cfg(test)]
mod tests {
    #[test]
    fn duplicate_crash() {
        let v = elements::hex::decode_to_vec("abcd").unwrap();
        super::do_test(&v);
    }
}
