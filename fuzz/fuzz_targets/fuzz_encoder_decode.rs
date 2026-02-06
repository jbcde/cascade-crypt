#![no_main]
use libfuzzer_sys::fuzz_target;
use cascrypt::encoder;

fuzz_target!(|data: &str| {
    let _ = encoder::decode(data);
});
