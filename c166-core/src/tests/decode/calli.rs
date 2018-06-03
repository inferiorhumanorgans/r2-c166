test_requires_decode!();

#[test]
fn op_ab() {
    test_disasm_op!([0xAB, 0x34], "calli cc_NZ, [r4]");
}
