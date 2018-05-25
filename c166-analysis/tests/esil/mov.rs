use ::common::*;

#[test]
fn esil_mov_f0() {
    assert_eq!(r2_eval_asm_op_reg_with_init("F072", "r7", "dr r2=0x22"), "0x00000022");
}

#[test]
fn esil_mov_e0() {
    assert_eq!(r2_eval_asm_op_reg("E0F7", "r7"), "0x0000000f");
}

#[test]
fn esil_mov_e6() {
    assert_eq!(r2_eval_asm_op_reg("E6F71234", "r7"), "0x00003412");
}

#[test]
fn esil_mov_a8() {
    assert_eq!(r2_eval_asm_op_reg_with_init("A872", "r7", "dr r2=0x8;s 8;wx 1234;s 0"), "0x00003412");
}

#[test]
fn esil_mov_98() {
    assert_eq!(r2_eval_asm_op_reg_with_init("9872", "r7", "dr r2=0x8;s 8;wx 1234;s 0"), "0x00003412");
    assert_eq!(r2_eval_asm_op_reg_with_init("9872", "r2", "dr r2=0x8;s 8;wx 1234;s 0"), "0x0000000a");
}

#[test]
fn esil_mov_b8() {
    assert_eq!(r2_eval_asm_op_reg_with_init("9872", "r7", "dr r2=0x8;s 8;wx 1234;s 0"), "0x00003412");
    assert_eq!(r2_eval_asm_op_reg_with_init("9872", "r2", "dr r2=0x8;s 8;wx 1234;s 0"), "0x0000000a");
}
