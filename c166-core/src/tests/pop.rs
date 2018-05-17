test_requires!();

#[test]
fn c166_op_fc() {
    test_disasm_op!([0xFC, 0x07], "pop MDL");
}
