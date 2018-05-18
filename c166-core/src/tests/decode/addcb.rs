test_requires!();

#[test]
fn c166_op_11() {
    test_disasm_op!([0x11, 0x44], "addcb rl2, rl2");
}

#[test]
fn c166_op_19_1() {
    test_disasm_op!([0x19, (0x04 << 4) | (0b10 << 2) | 0x03], "addcb rl2, [r3]");
}

#[test]
fn c166_op_19_2() {
    test_disasm_op!([0x19, (0x04 << 4) | (0b11 << 2) | 0x03], "addcb rl2, [r3+]");
}

#[test]
fn c166_op_19_3() {
    test_disasm_op!([0x19, (0x04 << 4) | (0b00 << 2) | 0x04], "addcb rl2, #04h");
}

#[test]
fn c166_op_17() {
    test_disasm_op!([0x17, 0x03, 0x56, 0x78], "addcb DPP3, #56h");
}

#[test]
fn c166_op_13() {
    test_disasm_op!([0x13, 0x03, 0x56, 0x78], "addcb DPP3, 7856h");
}

#[test]
fn c166_op_15() {
    test_disasm_op!([0x15, 0x03, 0x56, 0x78], "addcb 7856h, DPP3");
}

