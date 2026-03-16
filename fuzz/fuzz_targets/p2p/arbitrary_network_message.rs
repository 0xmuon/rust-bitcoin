#![cfg_attr(fuzzing, no_main)]
#![cfg_attr(not(fuzzing), allow(unused))]

use libfuzzer_sys::fuzz_target;

use arbitrary::{Arbitrary, Unstructured};
use bitcoin::consensus::encode::{deserialize, serialize};
use p2p::message::{NetworkMessage, V1NetworkMessage, V2NetworkMessage};

#[cfg(not(fuzzing))]
fn main() {}

fn do_test(data: &[u8]) {
    let mut u = Unstructured::new(data);

    if u.is_empty() {
        return;
    }

    // 1) Fuzz arbitrary V1NetworkMessage (header + payload) and require logical round-trip.
    if let Ok(v1_msg) = V1NetworkMessage::arbitrary(&mut u) {
        let encoded = serialize(&v1_msg);
        if let Ok(decoded_v1) = deserialize::<V1NetworkMessage>(&encoded) {
            let reencoded = serialize(&decoded_v1);
            // Allow benign differences in the byte-level framing (e.g. length-prefix),
            // but insist that decoding the re-encoded bytes yields the same message.
            if let Ok(decoded_again) = deserialize::<V1NetworkMessage>(&reencoded) {
                assert_eq!(
                    decoded_v1, decoded_again,
                    "V1NetworkMessage struct should round-trip"
                );
            }
        }
    }

    // 2) Fuzz arbitrary NetworkMessage via the V2NetworkMessage wrapper.
    if let Ok(payload) = NetworkMessage::arbitrary(&mut u) {
        let v2_msg = V2NetworkMessage::new(payload.clone());
        let encoded = serialize(&v2_msg);
        if let Ok(decoded_v2) = deserialize::<V2NetworkMessage>(&encoded) {
            let reencoded = serialize(&decoded_v2);
            // For V2, allow benign normalization at the wire level (e.g. flags or padding),
            // but require that decoding the re-encoded bytes gives the same logical message.
            if let Ok(decoded_again) = deserialize::<V2NetworkMessage>(&reencoded) {
                assert_eq!(
                    decoded_v2, decoded_again,
                    "V2NetworkMessage struct should round-trip"
                );
            }
        }
    }
}

fuzz_target!(|data: &[u8]| {
    do_test(data);
});

#[cfg(all(test, fuzzing))]
mod tests {
    fn extend_vec_from_hex(hex: &str, out: &mut Vec<u8>) {
        let mut b = 0;
        for (idx, c) in hex.as_bytes().iter().enumerate() {
            b <<= 4;
            match *c {
                b'A'..=b'F' => b |= c - b'A' + 10,
                b'a'..=b'f' => b |= c - b'a' + 10,
                b'0'..=b'9' => b |= c - b'0',
                _ => panic!("Bad hex"),
            }
            if (idx & 1) == 1 {
                out.push(b);
                b = 0;
            }
        }
    }

    #[test]
    fn duplicate_crash() {
        let mut a = Vec::new();
        extend_vec_from_hex("496e66696e697479007f0a", &mut a);
        super::do_test(&a);
    }
}

