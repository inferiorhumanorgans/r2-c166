test_requires!();

#[test]
fn c166_op_5b_1() {
    test_disasm_op!([0x5B, 0x44], "divu r4");
}

#[test]
#[should_panic(expected = "Instruction was invalid")]
fn c166_op_5b_2() {
    test_disasm_op!([0x5B, 0x34], "invalid");
}
