test_requires!();

#[test]
fn c166_op_db_1() {
    test_disasm_op!([0xDB, 0x00], "rets");
}

#[test]
#[should_panic(expected = "Instruction was invalid")]
fn c166_op_db_2() {
    test_disasm_op!([0xDB, 0xFF], "invalid");
}
