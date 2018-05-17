test_requires!();

#[test]
fn c166_op_91_1() {
    test_disasm_op!([0x91, 0x40], "cpl r4");
}

#[test]
#[should_panic(expected = "Instruction was invalid")]
fn c166_op_91_2() {
    test_disasm_op!([0x91, 0x44], "invalid");
}
