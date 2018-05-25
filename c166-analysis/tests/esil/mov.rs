use ::common::*;

#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[test]
fn esil_mov_f0() {
    assert_eq!(r2_eval_asm_op_reg_with_init("F072", "r7", "ar r2=0x22"), "0x00000022");
}

#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[test]
fn esil_mov_e0() {
    assert_eq!(r2_eval_asm_op_reg("E0F7", "r7"), "0x0000000f");
}

#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[test]
fn esil_mov_e6() {
    assert_eq!(r2_eval_asm_op_reg("E6F71234", "r7"), "0x00003412");
}

#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[test]
fn esil_mov_a8() {
    assert_eq!(r2_eval_asm_op_reg_with_init("A872", "r7", "ar r2=0x8;s 8;wx 1234;s 0"), "0x00003412");
}

#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[test]
fn esil_mov_98() {
    let instruction : &str = "9872";
    let init_cmd : &str = "ar r2=0x8;s 8;wx 1234;s 0";
    assert_eq!(r2_eval_asm_op_reg_with_init(instruction, "r7", init_cmd), "0x00003412");
    assert_eq!(r2_eval_asm_op_reg_with_init(instruction, "r2", init_cmd), "0x0000000a");
}

#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[test]
fn esil_mov_b8() {
    // Write instruction 'B8 72' to 0x00
    // Run setup r2 command 'ar r2=0x8;ar r7=0x1234'
    // Dereference r2
    // Hope it equals 0x1234
    assert_eq!(r2_eval_asm_op_indirect_with_init("B872", "r2", "ar r2=0x8;ar r7=0x1234"), "0x1234");
}


#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[test]
fn esil_mov_88() {
    // Write instruction '88 72' to 0x00
    // r2 = source
    // r7 = dest
    // Run setup r2 command 'ar r2=0x1234;ar r7=0x8'
    // Dereference r7
    // Hope it equals 0x1234 which we wrote to 0x0006
    let instruction : &str = "8872";
    let init_cmd : &str = "ar r2=0x7890;ar r7=0x8;";

    assert_eq!(r2_eval_asm_op_indirect_with_init(instruction, "r7", init_cmd), "0x7890");
}

#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[test]
fn esil_mov_c8() {
    let instruction : &str = "C872";
    let init_cmd : &str = "ar z=1; ar r2=0x04; s 4; wx 9078;ar r7=0x8";

    assert_eq!(r2_eval_asm_op_indirect_with_init(instruction, "r7", init_cmd), "0x7890");

    // Zero flag should be cleared
    assert_eq!(r2_eval_asm_op_reg_with_init(instruction, "z", init_cmd), "0x00000000");
}

