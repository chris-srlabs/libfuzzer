#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| signal_matrix_harness::run(data));
