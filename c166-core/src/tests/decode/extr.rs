test_requires!();

#[test]
fn c166_op_d1() {
    test_disasm_op!([0xD1, (0b10 << 6) | (0x2 << 4) | 0x0F], "extr #3");
}
