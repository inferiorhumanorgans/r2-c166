test_requires!();

#[test]
fn c166_op_8a_1() {
    test_disasm_op!([0x8A, 0xF5, 0x0A, 0xF0], "jb r5.15, +0Ah");
}

#[test]
#[should_panic(expected = "Instruction was invalid")]
fn c166_op_8a_2() {
    test_disasm_op!([0x8A, 0xF5, 0x0A, 0xF4], "invalid");
}
