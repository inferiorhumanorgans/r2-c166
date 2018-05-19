test_requires!();

#[test]
fn c166_op_0d() {
    test_disasm_op!([0x0D, 0x38], "jmpr cc_UC, 0070h");
}

#[test]
fn c166_op_5d() {
    test_disasm_op!([0x5D, 0x38], "jmpr cc_NV, 0070h");
}
