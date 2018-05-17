test_requires!();

#[test]
fn c166_op_0b() {
    test_disasm_op!([0x0B, 0x10], "mul r1, r0");
}
