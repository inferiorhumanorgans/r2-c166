test_requires!();

#[test]
fn c166_op_41() {
    test_disasm_op!([0x41, 0x44], "cmpb rl2, rl2");
}

#[test]
fn c166_op_49_1() {
    test_disasm_op!([0x49, (0x04 << 4) | (0b10 << 2) | 0x03], "cmpb rl2, [r3]");
}

#[test]
fn c166_op_49_2() {
    test_disasm_op!([0x49, (0x04 << 4) | (0b11 << 2) | 0x03], "cmpb rl2, [r3+]");
}

#[test]
fn c166_op_49_3() {
    test_disasm_op!([0x49, (0x04 << 4) | (0b00 << 2) | 0x04], "cmpb rl2, #04h");
}

#[test]
fn c166_op_47() {
    test_disasm_op!([0x47, 0x03, 0x56, 0x78], "cmpb DPP3, #56h");
}

#[test]
fn c166_op_43() {
    test_disasm_op!([0x43, 0x03, 0x56, 0x78], "cmpb DPP3, 7856h");
}

