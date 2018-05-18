test_requires!();

#[test]
fn c166_op_6a() {
    test_disasm_op!([0x6A, 0x74, 0x76, 0xFF], "band FDECh.15, FDE8h.15");
}
