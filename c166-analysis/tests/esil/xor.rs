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
    let instruction : &str = "56F71000";
    let init_cmd : &str = "ar e=0; ar z=1; ar v=1; ar c=1; ar n=1; ar r7=0x00FF";
    assert_eq!(r2_eval_asm_op_reg_with_init(instruction, "r7", init_cmd), 0x00EF);
    // assert_eq!(r2_eval_asm_op_reg_with_init(instruction, "e", init_cmd), 0x0000);
    assert_eq!(r2_eval_asm_op_reg_with_init(instruction, "z", init_cmd), 0x0000);
    assert_eq!(r2_eval_asm_op_reg_with_init(instruction, "v", init_cmd), 0x0000);
    assert_eq!(r2_eval_asm_op_reg_with_init(instruction, "c", init_cmd), 0x0000);
    // assert_eq!(r2_eval_asm_op_reg_with_init(instruction, "n", init_cmd), 0x0000);
}
