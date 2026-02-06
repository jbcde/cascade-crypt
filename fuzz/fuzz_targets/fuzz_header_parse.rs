#![no_main]
use libfuzzer_sys::fuzz_target;
use cascrypt::Header;

fuzz_target!(|data: &[u8]| {
    let _ = Header::parse(data);
});
