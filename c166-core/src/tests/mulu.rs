test_requires!();

#[test]
fn c166_op_1b() {
    test_disasm_op!([0x1B, 0x10], "mulu r1, r0");
}
