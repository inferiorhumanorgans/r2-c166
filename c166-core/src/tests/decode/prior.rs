test_requires_decode!();

#[test]
fn op_2b() {
    test_disasm_op!([0x2B, 0x48], "prior r4, r8");
}
