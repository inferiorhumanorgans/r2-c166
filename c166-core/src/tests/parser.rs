/*
    This file is part of r2-c166.

    r2-c166 is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    r2-c166 is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with r2-c166.  If not, see <http://www.gnu.org/licenses/>.
*/

use std::str;

use ::instruction::*;
use ::reg::*;

use ::parser::*;

// Operand::GeneralWordRegister
#[test]
fn decode_gpr_word() {
    eprintln!("UGH");
    let op = asm_line("mov r12\0").unwrap().1;
    match &op.operands[0] {
        Operand::Register(reg) => {
            assert_eq!(*reg, Reg::R12, "Register did not match");
        }
        _ => assert!(false, "Expected Operand::GeneralWordRegister, got: {:?}", op.operands[0])
    }
}

// Operand::Register
#[test]
fn decode_gpr_byte_1() {
    eprintln!("UGH");
    let op = asm_line("mov rl1\0").unwrap().1;
    match &op.operands[0] {
        Operand::Register(reg) => {
            assert_eq!(*reg, Reg::RL1, "Register did not match");
        }
        _ => assert!(false, "Expected Operand::Register, got: {:?}", op.operands[0])
    }
}

#[test]
fn decode_gpr_byte_2() {
    eprintln!("UGH");
    let op = asm_line("mov rh1\0").unwrap().1;
    match &op.operands[0] {
        Operand::Register(reg) => {
            assert_eq!(*reg, Reg::RH1, "Register did not match");
        }
        _ => assert!(false, "Expected Operand::Register, got: {:?}", op.operands[0])
    }
}

// Operand::Register
#[test]
fn decode_reg() {
    eprintln!("UGH");
    let op = asm_line("mov ONES\0").unwrap().1;
    match op.operands[0] {
        Operand::Register(reg) => {
            assert_eq!(reg, Reg::ONES, "Register did not match");
        }
        _ => assert!(false, "Expected Operand::Register, got: {:?}", op.operands[0])
    }
}

// Operand::Direct
#[test]
fn decode_direct() {
    eprintln!("UGH");
    let op = asm_line("mov 12h\0").unwrap().1;
    match &op.operands[0] {
        Operand::Direct(value, _width) => {
            assert_eq!(*value, 0x12)
        }
        _ => assert!(false, "Expected Operand::Direct, got: {:?}", op.operands[0])
    }
}

// Operand::Indirect
#[test]
fn decode_indirect() {
    eprintln!("UGH");
    let op = asm_line("mov [r5]\0").unwrap().1;
    match &op.operands[0] {
        Operand::Indirect(value) => {
            assert_eq!(*value, Reg::R5)
        }
        _ => assert!(false, "Expected Operand::Indirect, got: {:?}", op.operands[0])
    }
}

// Operand::IndirectPostIncrement
#[test]
fn decode_indirect_post_inc() {
    eprintln!("UGH");
    let op = asm_line("mov [r8+]\0").unwrap().1;
    match &op.operands[0] {
        Operand::IndirectPostIncrement(reg) => {
            assert_eq!(*reg, Reg::R8)
        }
        _ => assert!(false, "Expected Operand::Immediate, got: {:?}", op.operands[0])
    }
}

// Operand::IndirectPreDecrement
#[test]
fn decode_indirect_pre_dec() {
    eprintln!("UGH");
    let op = asm_line("mov [-r2]\0").unwrap().1;
    match &op.operands[0] {
        Operand::IndirectPreDecrement(reg) => {
            assert_eq!(*reg, Reg::R2)
        }
        _ => assert!(false, "Expected Operand::Immediate, got: {:?}", op.operands[0])
    }
}

// Operand::IndirectAndImmediate
#[test]
fn decode_indirect_with_immediate() {
    eprintln!("UGH");
    let op = asm_line("mov [r5+#20h]\0").unwrap().1;
    match &op.operands[0] {
        Operand::IndirectAndImmediate(reg, immed) => {
            assert_eq!(*reg, Reg::R5);
            assert_eq!(*immed, 0x20);
        }
        _ => assert!(false, "Expected Operand::Immediate, got: {:?}", op.operands[0])
    }
}

// Operand::Immediate
#[test]
fn decode_immed() {
    eprintln!("UGH");
    let op = asm_line("mov #12h\0").unwrap().1;
    match &op.operands[0] {
        Operand::Immediate(value, _width) => {
            assert_eq!(*value, 0x12)
        }
        _ => assert!(false, "Expected Operand::Immediate, got: {:?}", op.operands[0])
    }
}

#[test]
fn test_single_statement() {
    let raw: &[u8] = b"mov #12h\0";
    let s : &str =  str::from_utf8(raw).unwrap();
    let asm_op = asm_line(s).unwrap().1;
    println!("OP: {:?}", asm_op);
    assert_eq!(asm_op.mnem, "mov");
    match asm_op.operands[0] {
        Operand::Immediate(0x12, 0) => {}
        _ => assert!(false, "Operand should have been #12h")
    }
}
