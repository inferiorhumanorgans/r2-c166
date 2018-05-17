test_requires!();

#[test]
fn c166_op_dc() {
    test_disasm_op!([0xDC, (0b00 << 6) | (0x3 << 4) | 0x0F], "exts r15, #4");
}

#[test]
fn c166_op_d7_1() {
    test_disasm_op!([0xD7, (0b00 << 6) | (0x3 << 4) | 0x00, 0x20, 0x00], "exts #20h, #4");
}

#[test]
#[should_panic(expected = "Instruction was invalid")]
fn c166_op_d7_2() {
    test_disasm_op!([0xD7, (0b00 << 6) | (0x3 << 4) | 0x05, 0x20, 0x00], "invalid");
}

#[test]
#[should_panic(expected = "Instruction was invalid")]
fn c166_op_d7_3() {
    test_disasm_op!([0xD7, (0b00 << 6) | (0x3 << 4) | 0x05, 0x20, 0x40], "invalid");
}
