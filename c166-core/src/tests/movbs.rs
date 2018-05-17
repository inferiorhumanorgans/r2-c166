test_requires!();

#[test]
fn c166_op_d0() {
    test_disasm_op!([0xD0, 0x44], "movbs r4, rl2");
}

#[test]
fn c166_op_d2() {
    test_disasm_op!([0xD2, 0x06, 0x10, 0x01], "movbs MDH, 0110h");
}

#[test]
fn c166_op_d5() {
    test_disasm_op!([0xD5, 0x06, 0x10, 0x01], "movbs 0110h, MDH");
}
