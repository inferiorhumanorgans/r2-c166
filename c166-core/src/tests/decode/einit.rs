test_requires!();

#[test]
fn c166_op_b5_1() {
    test_disasm_op!([0xB5, 0x4A, 0xB5, 0xB5], "einit");
}

#[test]
#[should_panic(expected = "Instruction was invalid")]
fn c166_op_b5_2() {
    test_disasm_op!([0xB5, 0x4A, 0xC5, 0xB5], "invalid");
}
