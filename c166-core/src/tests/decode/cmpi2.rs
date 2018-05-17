test_requires!();

#[test]
fn c166_op_90() {
    test_disasm_op!([0x90, 0x44], "cmpi2 r4, #04h");
}

#[test]
fn c166_op_96_1() {
    test_disasm_op!([0x96, 0xF4, 0x12, 0x34], "cmpi2 r4, #3412h");
}

#[test]
#[should_panic(expected = "Instruction was invalid")]
fn c166_op_96_2() {
    test_disasm_op!([0x96, 0xC4, 0x12, 0x34], "invalid");
}

#[test]
fn c166_op_92_1() {
    test_disasm_op!([0x92, 0xF4, 0x12, 0x34], "cmpi2 r4, 3412h");
}

#[test]
#[should_panic(expected = "Instruction was invalid")]
fn c166_op_92_2() {
    test_disasm_op!([0x92, 0xC4, 0x12, 0x34], "invalid");
}
