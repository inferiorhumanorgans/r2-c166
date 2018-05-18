test_requires!();

#[test]
fn c166_op_40() {
    test_disasm_op!([0x40, 0x44], "cmp r4, r4");
}

#[test]
fn c166_op_48_1() {
    test_disasm_op!([0x48, (0x04 << 4) | (0b10 << 2) | 0x03], "cmp r4, [r3]");
}

#[test]
fn c166_op_48_2() {
    test_disasm_op!([0x48, (0x04 << 4) | (0b11 << 2) | 0x03], "cmp r4, [r3+]");
}

#[test]
fn c166_op_48_3() {
    test_disasm_op!([0x48, (0x04 << 4) | (0b00 << 2) | 0x04], "cmp r4, #04h");
}

#[test]
fn c166_op_46() {
    test_disasm_op!([0x46, 0x03, 0x56, 0x78], "cmp DPP3, #7856h");
}

#[test]
fn c166_op_42() {
    test_disasm_op!([0x42, 0x03, 0x56, 0x78], "cmp DPP3, 7856h");
}

