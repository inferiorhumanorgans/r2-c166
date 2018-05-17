test_requires!();

#[test]
fn c166_op_7b() {
    test_disasm_op!([0x7B, 0x44], "divlu r4");
}
