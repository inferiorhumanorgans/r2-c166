test_requires!();

#[test]
fn c166_op_20() {
    test_disasm_op!([0x20, (0x03 << 4) | 0x06], "sub r3, r6");
}

#[test]
fn c166_op_28_1() {
    test_disasm_op!([0x28, (0x03 << 4) | (0b10 << 2) | 0x03], "sub r3, [r3]");
}

#[test]
fn c166_op_28_2() {
    test_disasm_op!([0x28, (0x03 << 4) | (0b11 << 2) | 0x03], "sub r3, [r3+]");
}

#[test]
fn c166_op_28_3() {
    test_disasm_op!([0x28, (0x03 << 4) | (0b00 << 2) | 0x05], "sub r3, #05h");
}

#[test]
fn c166_op_26() {
    test_disasm_op!([0x26, 0xC, 0xFF, 0xCC], "sub r12, #CCFFh");
}

#[test]
fn c166_op_22() {
    test_disasm_op!([0x22, 0xC, 0xFF, 0xCC], "sub r12, CCFFh");
}

#[test]
fn c166_op_24() {
    test_disasm_op!([0x24, 0xC, 0xFF, 0xCC], "sub CCFFh, r12");
}
