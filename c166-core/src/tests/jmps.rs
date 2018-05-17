test_requires!();

#[test]
fn c166_op_fa_1() {
    test_disasm_op!([0xFA, 0x0D, 0x2E, 0x98], "jmps 0Dh, 982Eh");
}
