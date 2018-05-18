test_requires!();

#[test]
fn c166_op_4a() {
    test_disasm_op!([0x4A, 0x74, 0x76, 0xFF], "bmov FDECh.15, FDE8h.15");
}
