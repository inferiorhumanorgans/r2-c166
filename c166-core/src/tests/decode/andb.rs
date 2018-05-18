test_requires!();

#[test]
fn c166_op_61() {
    test_disasm_op!([0x61, 0x44], "andb rl2, rl2");
}

#[test]
fn c166_op_69_1() {
    test_disasm_op!([0x69, (0x04 << 4) | (0b10 << 2) | 0x03], "andb rl2, [r3]");
}

#[test]
fn c166_op_69_2() {
    test_disasm_op!([0x69, (0x04 << 4) | (0b11 << 2) | 0x03], "andb rl2, [r3+]");
}

#[test]
fn c166_op_69_3() {
    test_disasm_op!([0x69, (0x04 << 4) | (0b00 << 2) | 0x04], "andb rl2, #04h");
}

#[test]
fn c166_op_67() {
    test_disasm_op!([0x67, 0x03, 0x56, 0x78], "andb DPP3, #56h");
}

#[test]
fn c166_op_63() {
    test_disasm_op!([0x63, 0x03, 0x56, 0x78], "andb DPP3, 7856h");
}

#[test]
fn c166_op_65() {
    test_disasm_op!([0x65, 0x03, 0x56, 0x78], "andb 7856h, DPP3");
}

