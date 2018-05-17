test_requires!();

#[test]
fn c166_op_b1_1() {
    test_disasm_op!([0xB1, 0x40], "cplb rl2");
}

#[test]
#[should_panic(expected = "Instruction was invalid")]
fn c166_op_b1_2() {
    test_disasm_op!([0xB1, 0x44], "invalid");
}
