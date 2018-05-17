test_requires!();

#[test]
fn c166_op_a7_1() {
    test_disasm_op!([0xA7, 0x58, 0xA7, 0xA7], "srvwdt");
}

#[test]
#[should_panic(expected = "Instruction was invalid")]
fn c166_op_a7_2() {
    test_disasm_op!([0xA7, 0x58, 0x00, 0xA7], "invalid");
}
