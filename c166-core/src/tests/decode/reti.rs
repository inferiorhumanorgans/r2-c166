test_requires_decode!();

#[test]
fn op_fb_1() {
    test_disasm_op!([0xFB, 0x88], "reti");
}

#[test]
fn op_fb_2() {
    test_disasm_op_failure!([0xFB, 0xFF]);
}
