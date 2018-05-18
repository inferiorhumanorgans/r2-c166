test_requires!();

#[test]
fn c166_op_d1_1() {
    test_disasm_op!([0xD1, (0b10 << 6) | (0x02 << 4) | 0x00], "extr #3");
}

#[test]
#[should_panic(expected = "Instruction was invalid")]
fn c166_op_d1_2() {
    test_disasm_op!([0xD1, (0b10 << 6) | (0x02 << 4) | 0x0F], "invalid");
}
