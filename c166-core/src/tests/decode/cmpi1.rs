test_requires!();

#[test]
fn c166_op_80() {
    test_disasm_op!([0x80, 0x44], "cmpi1 r4, #04h");
}

#[test]
fn c166_op_86_1() {
    test_disasm_op!([0x86, 0xF4, 0x12, 0x34], "cmpi1 r4, #3412h");
}

#[test]
#[should_panic(expected = "Instruction was invalid")]
fn c166_op_86_2() {
    test_disasm_op!([0x86, 0xC4, 0x12, 0x34], "invalid");
}

#[test]
fn c166_op_82_1() {
    test_disasm_op!([0x82, 0xF4, 0x12, 0x34], "cmpi1 r4, 3412h");
}

#[test]
#[should_panic(expected = "Instruction was invalid")]
fn c166_op_82_2() {
    test_disasm_op!([0x82, 0xC4, 0x12, 0x34], "invalid");
}
