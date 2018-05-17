test_requires!();

#[test]
fn c166_op_fb_1() {
    test_disasm_op!([0xFB, 0x88], "reti");
}

#[test]
#[should_panic(expected = "Instruction was invalid")]
fn c166_op_fb_2() {
    test_disasm_op!([0xFB, 0xFF], "invalid");
}
