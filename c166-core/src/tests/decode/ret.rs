test_requires_decode!();

#[test]
fn op_cb_1() {
    test_disasm_op!([0xCB, 0x00], "ret");
}

#[test]
fn op_cb_2() {
    test_disasm_op_failure!([0xCB, 0xFF]);
}
