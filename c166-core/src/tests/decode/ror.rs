test_requires_decode!();

#[test]
fn op_2c() {
    test_disasm_op!([0x2C, 0x15], "ror r1, r5");
}

#[test]
fn op_3c() {
    test_disasm_op!([0x3C, 0x51], "ror r1, #05h");
}
