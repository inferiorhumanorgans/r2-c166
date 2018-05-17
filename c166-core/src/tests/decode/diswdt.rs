test_requires!();

#[test]
fn c166_op_a5_1() {
    test_disasm_op!([0xA5, 0x5A, 0xA5, 0xA5], "diswdt");
}

#[test]
#[should_panic(expected = "Instruction was invalid")]
fn c166_op_a5_2() {
    test_disasm_op!([0xA5, 0x5A, 0xB5, 0xA5], "invalid");
}
