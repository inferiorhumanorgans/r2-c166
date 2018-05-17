test_requires!();

#[test]
fn c166_op_e2() {
    test_disasm_op!([0xE2, 0x02, 0x08, 0x80], "pcall DPP2, 8008h");
}
