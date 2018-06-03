test_requires_decode!();

#[test]
fn op_6b() {
    test_disasm_op!([0x6B, 0x44], "divl r4");
}
