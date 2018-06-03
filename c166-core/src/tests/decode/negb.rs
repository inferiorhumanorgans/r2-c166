test_requires_decode!();

#[test]
fn op_a1_1() {
    test_disasm_op!([0xA1, 0x10], "negb rh0");
}

#[test]
#[ignore]
#[should_panic(expected = "Instruction was invalid")]
fn op_a1_2() {
    test_disasm_op!([0xA1, 0x11], "invalid");
}
