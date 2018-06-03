test_requires_decode!();

#[test]
fn op_97_1() {
    test_disasm_op!([0x97, 0x68, 0x97, 0x97], "pwrdn");
}

#[test]
fn op_97_2() {
    test_disasm_op_failure!([0x97, 0x68, 0x97, 0x00]);
}
