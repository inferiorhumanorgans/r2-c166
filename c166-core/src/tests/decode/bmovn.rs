test_requires!();

#[test]
fn c166_op_3a() {
    test_disasm_op!([0x3A, 0x74, 0x76, 0xFF], "bmovn FDECh.15, FDE8h.15");
}
