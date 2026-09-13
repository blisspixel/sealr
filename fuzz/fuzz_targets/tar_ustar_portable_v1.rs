#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    sealr::__fuzz_tar_ustar_portable_v1(input);
});
