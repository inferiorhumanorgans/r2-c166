test_requires_decode!();

#[test]
fn op_00() {
    test_disasm_op!([0x00, 0x44], "add r4, r4");
}

#[test]
fn op_08_1() {
    test_disasm_op!([0x08, (0x04 << 4) | (0b10 << 2) | 0x03], "add r4, [r3]");
}

#[test]
fn op_08_2() {
    test_disasm_op!([0x08, (0x04 << 4) | (0b11 << 2) | 0x03], "add r4, [r3+]");
}

#[test]
fn op_08_3() {
    test_disasm_op!([0x08, (0x04 << 4) | (0b00 << 2) | 0x04], "add r4, #04h");
}

#[test]
fn op_06() {
    test_disasm_op!([0x06, 0x03, 0x56, 0x78], "add DPP3, #7856h");
}

#[test]
fn op_02() {
    test_disasm_op!([0x02, 0x03, 0x56, 0x78], "add DPP3, 7856h");
}

#[test]
fn op_04() {
    test_disasm_op!([0x04, 0x03, 0x56, 0x78], "add 7856h, DPP3");
}

