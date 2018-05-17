test_requires!();

#[test]
fn c166_op_ec() {
    test_disasm_op!([0xEC, 0xF8], "push r8");
}
