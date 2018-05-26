use ::common::*;

#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[test]
fn esil_xor_50() {
    assert_eq!(r2_eval_asm_op_reg_with_init("5072", "r7", "ar r7=0xFF; ar r2=0x10"), 0x00EF);
}


#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[test]
fn esil_xor_56() {
    // 0x00FF ^ 0x0010 = 0x00EF
    assert_eq!(r2_eval_asm_op_reg_with_init("56F71000", "r7", "ar r7=0x00FF"), 0x00EF);
}
