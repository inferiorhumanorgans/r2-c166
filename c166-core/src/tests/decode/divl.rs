test_requires!();

#[test]
fn c166_op_6b() {
    test_disasm_op!([0x6B, 0x44], "divl r4");
}
