test_requires!();

#[test]
fn c166_op_4b() {
    test_disasm_op!([0x4B, 0x44], "div r4");
}
