test_requires_decode!();

#[test]
fn op_ac() {
    test_disasm_op!([0xAC, 0x34], "ashr r3, r4");
}

#[test]
fn op_bc() {
    test_disasm_op!([0xBC, 0x4F], "ashr r15, #04h");
}
