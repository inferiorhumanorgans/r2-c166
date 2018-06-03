test_requires_decode!();

#[test]
fn op_db_1() {
    test_disasm_op!([0xDB, 0x00], "rets");
}

#[test]
fn op_db_2() { test_disasm_op_failure!([0xDB, 0xFF]); }
