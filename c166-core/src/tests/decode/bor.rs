test_requires!();

#[test]
fn c166_op_5a() {
    test_disasm_op!([0x5A, 0x74, 0x76, 0xFF], "bor FDECh.15, FDE8h.15");
}
