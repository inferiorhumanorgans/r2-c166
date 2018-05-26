use ::common::*;

#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[test]
fn esil_mov_f0() {
    assert_eq!(r2_eval_asm_op_reg_with_init("F072", "r7", "ar r2=0x22"), 0x0022);
}

#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[test]
fn esil_mov_e0() {
    assert_eq!(r2_eval_asm_op_reg("E0F7", "r7"), 0x000F);
}

#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[test]
fn esil_mov_e6() {
    assert_eq!(r2_eval_asm_op_reg("E6F71234", "r7"), 0x3412);
}

#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[test]
fn esil_mov_a8() {
    assert_eq!(r2_eval_asm_op_reg_with_init("A872", "r7", "ar r2=0x8;s 8;wx 1234;s 0"), 0x3412);
}

#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[test]
fn esil_mov_98() {
    let instruction : &str = "9872";
    let init_cmd : &str = "ar r2=0x8;s 8;wx 1234;s 0";
    assert_eq!(r2_eval_asm_op_reg_with_init(instruction, "r7", init_cmd), 0x3412);
    assert_eq!(r2_eval_asm_op_reg_with_init(instruction, "r2", init_cmd), 0x000A);
}

#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[test]
fn esil_mov_b8() {
    // Write instruction 'B8 72' to 0x00
    // Run setup r2 command 'ar r2=0x8;ar r7=0x1234'
    // Dereference r2
    // Hope it equals 0x1234
    assert_eq!(r2_eval_asm_op_indirect_with_init("B872", "r2", "ar r2=0x8;ar r7=0x1234"), 0x1234);
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

    assert_eq!(r2_eval_asm_op_indirect_with_init(instruction, "r7", init_cmd), 0x7890);
}

#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[test]
fn esil_mov_c8() {
    let instruction : &str = "C872";
    let init_cmd : &str = "ar z=1; ar r2=0x04; s 4; wx 9078;ar r7=0x8";

    assert_eq!(r2_eval_asm_op_indirect_with_init(instruction, "r7", init_cmd), 0x7890);

    // Zero flag should be cleared
    assert_eq!(r2_eval_asm_op_reg_with_init(instruction, "z", init_cmd), 0x0000);
}

#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[test]
fn esil_mov_c8_2() {
    let instruction : &str = "C872";
    let init_cmd : &str = "ar z=0; ar r2=0x04; s 4; wx 0000; ar r7=0x8";

    assert_eq!(r2_eval_asm_op_indirect_with_init(instruction, "r7", init_cmd), 0x0000);

    // Zero flag should be set
    assert_eq!(r2_eval_asm_op_reg_with_init(instruction, "z", init_cmd), 0x0001);
}

#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[test]
fn esil_mov_d8() {
    let instruction : &str = "D827";
    let init_cmd : &str = "ar z=0; ar r2=0x04; ar r7=0x8; s 0x8; wx 4567";

    assert_eq!(r2_eval_asm_op_reg_with_init(instruction, "r2", init_cmd), 0x0006);
    assert_eq!(r2_eval_asm_op_mem_with_init(instruction, "0x0004", init_cmd), 0x4567);

    // Zero flag should be clear
    assert_eq!(r2_eval_asm_op_reg_with_init(instruction, "z", init_cmd), 0x0000);
}

#[cfg_attr(not(feature = "integration-tests"), ignore)]
#[test]
fn esil_mov_e8() {
    let instruction : &str = "E827";
    let init_cmd : &str = "ar z=0; ar r2=0x04; ar r7=0x8; s 0x8; wx 4567";

    assert_eq!(r2_eval_asm_op_reg_with_init(instruction, "r7", init_cmd), 0x000A);
    assert_eq!(r2_eval_asm_op_mem_with_init(instruction, "0x0004", init_cmd), 0x4567);

    // Zero flag should be clear
    assert_eq!(r2_eval_asm_op_reg_with_init(instruction, "z", init_cmd), 0x0000);
}
