test_requires!();

#[test]
fn c166_op_b7_1() {
    test_disasm_op!([0xB7, 0x48, 0xB7, 0xB7], "srst");
}

#[test]
#[should_panic(expected = "Instruction was invalid")]
fn c166_op_b7_2() {
    test_disasm_op!([0xB7, 0x48, 0x00, 0xB7], "invalid");
}
