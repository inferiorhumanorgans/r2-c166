test_requires!();

#[test]
fn c166_op_aa_1() {
    test_disasm_op!([0xAA, 0xF5, 0x0A, 0xF0], "jbc r5.15, 0014h");
}

#[test]
#[should_panic(expected = "Instruction was invalid")]
fn c166_op_aa_2() {
    test_disasm_op!([0xAA, 0xF5, 0x0A, 0xF4], "invalid");
}
