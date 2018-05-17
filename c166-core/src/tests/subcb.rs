test_requires!();

#[test]
fn c166_op_31() {
    test_disasm_op!([0x31, (0x03 << 4) | 0x06], "subcb rh1, rl3");
}

#[test]
fn c166_op_39_1() {
    test_disasm_op!([0x39, (0x03 << 4) | (0b10 << 2) | 0x03], "subcb rh1, [r3]");
}

#[test]
fn c166_op_39_2() {
    test_disasm_op!([0x39, (0x03 << 4) | (0b11 << 2) | 0x03], "subcb rh1, [r3+]");
}

#[test]
fn c166_op_39_3() {
    test_disasm_op!([0x39, (0x03 << 4) | (0b00 << 2) | 0x05], "subcb rh1, #05h");
}

#[test]
fn c166_op_37() {
    test_disasm_op!([0x37, 0xFC, 0xFF, 0xCC], "subcb rl6, #FFh");
}

#[test]
fn c166_op_33() {
    test_disasm_op!([0x33, 0x0B, 0xFF, 0xCC], "subcb STKUN, CCFFh");
}

#[test]
fn c166_op_35() {
    test_disasm_op!([0x35, 0xFC, 0xFF, 0xCC], "subcb CCFFh, rl6");
}
