test_requires_decode!();

#[test]
fn op_cc_1() {
    test_disasm_op!([0xCC, 0x00], "nop");
}

#[test]
fn op_cc_2() {
    test_disasm_op_failure!([0xCC, 0xDD]);
}
