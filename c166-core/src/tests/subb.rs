test_requires!();

#[test]
fn c166_op_21() {
    test_disasm_op!([0x21, (0x03 << 4) | 0x06], "subb rh1, rl3");
}

#[test]
fn c166_op_29_1() {
    test_disasm_op!([0x29, (0x03 << 4) | (0b10 << 2) | 0x03], "subb rh1, [r3]");
}

#[test]
fn c166_op_29_2() {
    test_disasm_op!([0x29, (0x03 << 4) | (0b11 << 2) | 0x03], "subb rh1, [r3+]");
}

#[test]
fn c166_op_29_3() {
    test_disasm_op!([0x29, (0x03 << 4) | (0b00 << 2) | 0x05], "subb rh1, #05h");
}

#[test]
fn c166_op_27() {
    test_disasm_op!([0x27, 0xC, 0xFF, 0xCC], "subb rl6, #FFh");
}

#[test]
fn c166_op_23() {
    test_disasm_op!([0x23, 0xC, 0xFF, 0xCC], "subb rl6, CCFFh");
}

#[test]
fn c166_op_25() {
    test_disasm_op!([0x25, 0xC, 0xFF, 0xCC], "subb CCFFh, rl6");
}
