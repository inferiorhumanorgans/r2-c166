test_requires!();

#[test]
fn c166_op_9b() {
    test_disasm_op!([0x9B, 0x7A], "trap #3Dh");
}
