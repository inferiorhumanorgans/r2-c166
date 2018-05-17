test_requires!();

#[test]
fn c166_op_ba_1() {
    test_disasm_op!([0xBA, 0xF2, 0x01, 0xF0], "jnbs r2.15, +01h"); // Need to know CP
}

#[test]
#[should_panic(expected = "Instruction was invalid")]
fn c166_op_ba_2() {
    test_disasm_op!([0xBA, 0xF2, 0x01, 0xF3], "jnbs r2.15, D96D6h");
}

