test_requires_decode!();

#[test]
fn op_01() {
    test_disasm_op!([0x01, 0x44], "addb rl2, rl2");
}

#[test]
fn op_09_1() {
    test_disasm_op!([0x09, (0x04 << 4) | (0b10 << 2) | 0x03], "addb rl2, [r3]");
}

#[test]
fn op_09_2() {
    test_disasm_op!([0x09, (0x04 << 4) | (0b11 << 2) | 0x03], "addb rl2, [r3+]");
}

#[test]
fn op_09_3() {
    test_disasm_op!([0x09, (0x04 << 4) | (0b00 << 2) | 0x04], "addb rl2, #04h");
}

#[test]
fn op_07() {
    test_disasm_op!([0x07, 0x03, 0x56, 0x78], "addb DPP3, #56h");
}

#[test]
fn op_03() {
    test_disasm_op!([0x03, 0x03, 0x56, 0x78], "addb DPP3, 7856h");
}

#[test]
fn op_05() {
    test_disasm_op!([0x05, 0x03, 0x56, 0x78], "addb 7856h, DPP3");
}

