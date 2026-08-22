#![allow(missing_docs)]

#[test]
fn one_time_noise_ownership_is_compile_time_enforced() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/trybuild/noise_not_clone.rs");
    tests.compile_fail("tests/trybuild/noise_cannot_be_reused.rs");
}
