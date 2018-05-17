test_requires!();

#[test]
fn c166_op_30() {
    test_disasm_op!([0x30, (0x03 << 4) | 0x06], "subc r3, r6");
}

#[test]
fn c166_op_38_1() {
    test_disasm_op!([0x38, (0x03 << 4) | (0b10 << 2) | 0x03], "subc r3, [r3]");
}

#[test]
fn c166_op_38_2() {
    test_disasm_op!([0x38, (0x03 << 4) | (0b11 << 2) | 0x03], "subc r3, [r3+]");
}

#[test]
fn c166_op_38_3() {
    test_disasm_op!([0x38, (0x03 << 4) | (0b00 << 2) | 0x05], "subc r3, #05h");
}

#[test]
fn c166_op_36() {
    test_disasm_op!([0x36, 0xC, 0xFF, 0xCC], "subc r12, #CCFFh");
}

#[test]
fn c166_op_32() {
    test_disasm_op!([0x32, 0xC, 0xFF, 0xCC], "subc r12, CCFFh");
}

#[test]
fn c166_op_34() {
    test_disasm_op!([0x34, 0xC, 0xFF, 0xCC], "subc CCFFh, r12");
}
