test_requires_decode!();

#[test]
fn op_ea_1() {
    test_disasm_op!([0xEA, 0x00, 0x01, 0x05], "jmpa cc_UC, 0501h");
}

#[test]
fn op_ea_2() {
    test_disasm_op!([0xEA, 0x70, 0x01, 0x05], "jmpa cc_NN, 0501h");
}

#[test]
#[should_panic(expected = "Instruction was invalid")]
fn op_ea_3() {
    test_disasm_op!([0xEA, 0x75, 0x01, 0x05], "invalid");
}
