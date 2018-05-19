test_requires!();

#[test]
fn c166_op_bb() {
    test_disasm_op!([0xBB, 0x03, 0x12, 0x34], "callr 0006h");
}
