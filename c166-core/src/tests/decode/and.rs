test_requires_decode!();

#[test]
fn op_60() {
    test_disasm_op!([0x60, 0x44], "and r4, r4");
}

#[test]
fn op_68_1() {
    test_disasm_op!([0x68, (0x04 << 4) | (0b10 << 2) | 0x03], "and r4, [r3]");
}

#[test]
fn op_68_2() {
    test_disasm_op!([0x68, (0x04 << 4) | (0b11 << 2) | 0x03], "and r4, [r3+]");
}

#[test]
fn op_68_3() {
    test_disasm_op!([0x68, (0x04 << 4) | (0b00 << 2) | 0x04], "and r4, #04h");
}

#[test]
fn op_66() {
    test_disasm_op!([0x66, 0x03, 0x56, 0x78], "and DPP3, #7856h");
}

#[test]
fn op_62() {
    test_disasm_op!([0x62, 0x03, 0x56, 0x78], "and DPP3, 7856h");
}

#[test]
fn op_64() {
    test_disasm_op!([0x64, 0x03, 0x56, 0x78], "and 7856h, DPP3");
}

