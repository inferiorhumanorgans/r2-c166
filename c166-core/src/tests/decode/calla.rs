test_requires!();

#[test]
fn c166_op_ca_1() {
    test_disasm_op!([0xCA, 0x70, 0x45, 0x67], "calla cc_NN, 6745h");
}

#[test]
#[should_panic(expected = "Instruction was invalid")]
fn c166_op_ca_2() {
    test_disasm_op!([0xCA, 0xF7, 0x45, 0x67], "invalid");
}
