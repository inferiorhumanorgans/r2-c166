test_requires!();

#[test]
fn c166_op_31() {
    test_disasm_op!([0x31, (0x03 << 4) | 0x06], "subcb rh1, rl3");
}
