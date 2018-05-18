test_requires!();

#[test]
fn c166_op_da() {
    test_disasm_op!([0xDA, 0x01, 0x12, 0x34], "calls 01h, 3412h");
}
