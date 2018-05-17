test_requires!();

#[test]
fn c166_op_cc_1() {
    test_disasm_op!([0xCC, 0x00], "nop");
}

#[test]
#[should_panic(expected = "Instruction was invalid")]
fn c166_op_cc_2() {
    test_disasm_op!([0xCC, 0xDD], "invalid");
}
