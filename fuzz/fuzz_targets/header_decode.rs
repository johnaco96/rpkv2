#![no_main]

use libfuzzer_sys::fuzz_target;
use rpkv2::fastpath::packet::Header;

fuzz_target!(|data: &[u8]| {
    let _ = Header::decode_from(data);
    let _ = Header::payload(data);
});
