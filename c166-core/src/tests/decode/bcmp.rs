test_requires!();

#[test]
fn c166_op_2a() {
    test_disasm_op!([0x2A, 0x74, 0x76, 0xFF], "bcmp FDECh.15, FDE8h.15");
}
