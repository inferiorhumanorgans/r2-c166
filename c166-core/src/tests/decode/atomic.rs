test_requires_decode!();

#[test]
fn op_d1_1() {
    test_disasm_op!([0xD1, (0x00 << 6) | (0x3 << 4) | 0x00], "atomic #4");
}

#[test]
#[should_panic(expected = "Instruction was invalid")]
fn op_d1_2() {
    test_disasm_op!([0xD1, (0x00 << 6) | (0x3 << 4) | 0x05], "invalid");
}
