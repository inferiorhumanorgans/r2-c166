test_requires!();

#[test]
fn c166_op_1a() {
    test_disasm_op!([0x1A, 0xB7, 0x80, 0x80], "bfldh S0RIC, #80h, #80h");
}
