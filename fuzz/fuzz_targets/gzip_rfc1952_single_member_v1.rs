#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    sealr::__fuzz_gzip_rfc1952_single_member_v1(input);
});
