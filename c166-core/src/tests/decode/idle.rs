test_requires_decode!();

#[test]
fn op_87_1() {
    test_disasm_op!([0x87, 0x78, 0x87, 0x87], "idle");
}

#[test]
#[should_panic(expected = "Instruction was invalid")]
fn op_87_2() {
    test_disasm_op!([0x87, 0x78, 0x07, 0x87], "invalid");
}
