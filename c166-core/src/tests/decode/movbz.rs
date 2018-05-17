test_requires!();

#[test]
fn c166_op_c0() {
    test_disasm_op!([0xC0, 0x44], "movbz r4, rl2");
}

#[test]
fn c166_op_c2() {
    test_disasm_op!([0xC2, 0x06, 0x10, 0x01], "movbz MDH, 0110h");
}

#[test]
fn c166_op_c5() {
    test_disasm_op!([0xC5, 0x06, 0x10, 0x01], "movbz 0110h, MDH");
}
