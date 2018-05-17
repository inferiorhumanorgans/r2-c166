test_requires!();

#[test]
fn c166_op_cb_1() {
    test_disasm_op!([0xCB, 0x00], "ret");
}

#[test]
#[should_panic(expected = "Instruction was invalid")]
fn c166_op_cb_2() {
    test_disasm_op!([0xCB, 0xFF], "invalid");
}
