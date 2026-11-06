fn main() {
    libfuzzer_sys::fuzz!(|data: &[u8]| signal_matrix_harness::run(data));
}
