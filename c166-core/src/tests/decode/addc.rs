test_requires_decode!();

#[test]
fn op_10() {
    test_disasm_op!([0x10, 0x44], "addc r4, r4");
}

#[test]
fn op_18_1() {
    test_disasm_op!([0x18, (0x04 << 4) | (0b10 << 2) | 0x03], "addc r4, [r3]");
}

#[test]
fn op_18_2() {
    test_disasm_op!([0x18, (0x04 << 4) | (0b11 << 2) | 0x03], "addc r4, [r3+]");
}

#[test]
fn op_18_3() {
    test_disasm_op!([0x18, (0x04 << 4) | (0b00 << 2) | 0x04], "addc r4, #04h");
}

#[test]
fn op_16() {
    test_disasm_op!([0x16, 0x03, 0x56, 0x78], "addc DPP3, #7856h");
}

#[test]
fn op_12() {
    test_disasm_op!([0x12, 0x03, 0x56, 0x78], "addc DPP3, 7856h");
}

#[test]
fn op_14() {
    test_disasm_op!([0x14, 0x03, 0x56, 0x78], "addc 7856h, DPP3");
}

