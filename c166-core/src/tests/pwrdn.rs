test_requires!();

#[test]
fn c166_op_97_1() {
    test_disasm_op!([0x97, 0x68, 0x97, 0x97], "pwrdn");
}

#[test]
#[should_panic(expected = "Instruction was invalid")]
fn c166_op_97_2() {
    test_disasm_op!([0x97, 0x68, 0x97, 0x00], "invalid");
}
