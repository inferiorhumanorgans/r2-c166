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

use std::fmt;

use ::instruction::*;
use ::bitaddr::*;

impl<'a> fmt::Display for Operand {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self {

            Operand::BitAddr(offset, bit)               => {
                let mnem = bitoff_to_string(*offset as u8, false).unwrap();
                match bit {
                    0xFF        => write!(f, "{}", mnem),
                    0x10..=0xFF  =>  panic!("BitAddr requires a bit offset 0x00..=0x0F"),
                    _           => write!(f, "{}.{}", mnem, bit)
                }
            },
            Operand::Register(r)                    => { write!(f, "{}", r) },                  // SFR, ESFR, GPR
            Operand::Direct(d, width)               => {
                match width {
                    2 => write!(f, "{:X}", d),
                    4 |
                    8 => write!(f, "{:02X}h", d),
                    _ => write!(f, "{:04X}h", d)
                }
            }, // mem, caddr, seg, rel
            Operand::Indirect(r)                    => { write!(f, "[{}]", r) }, // [GPR],
            Operand::IndirectPostIncrement(r)       => { write!(f, "[{}+]", r) }, // [GPR+]
            Operand::IndirectPreDecrement(r)        => { write!(f, "[-{}]", r) }, // [-GPR]
            Operand::IndirectAndImmediate(ind, imm) => { write!(f, "[{} + #{:X}h]", ind, imm) }, // [GPR+DATA16],
            Operand::Immediate(imm, width)          => { // #data3, #data4, #data8, #data16, #mask8, #trap7, #pag10, #seg8, #irang2
                match width {
                    2 => write!(f, "#{:X}", imm),
                    3 |
                    4 |
                    7 |
                    8 => write!(f, "#{:02X}h", imm),
                    10 |
                    16 => write!(f, "#{:04X}h", imm),
                    _ => write!(f, "{:X}h", imm),
                }
            },
            Operand::Condition(c)                   => { write!(f, "{}", c) },
        }
    }
}

pub fn expand_op(op: &Operand, op_type: &OperandType, pc: u32) -> String {
    if let Operand::Direct(d, _) = op {
        if let OperandType::DirectRelative8S = *op_type {
            let direct: u16 = *d;
            return format!("{}", Operand::Direct((direct * 2) + (pc as u16), 16));
        }
    }

    format!("{}", op)
}

pub fn format_op(isn: &Instruction, values: &InstructionArguments, pc: u32) -> String {
    let mnemonic = match values.mnemonic.as_ref() {
        Some(mnem) => mnem,
        _ => isn.mnemonic,
    };

     match (&isn.op1, &isn.op2, &isn.op3) {
         (None, None, None) => {
             format!("{}", mnemonic)
         }
         (Some(ref op1), None, None) => {
             let val1 = expand_op(values.op1.as_ref().unwrap(), &op1, pc);
             format!("{} {}", mnemonic, val1)
         },
         (Some(ref op1), Some(ref op2), None) => {
             let val1 = expand_op(values.op1.as_ref().unwrap(), &op1, pc);
             let val2 = expand_op(values.op2.as_ref().unwrap(), &op2, pc);
             format!("{} {}, {}", mnemonic, val1, val2)
         },
         (Some(ref op1), Some(ref op2), Some(ref op3)) => {
             let val1 = expand_op(values.op1.as_ref().unwrap(), &op1, pc);
             let val2 = expand_op(values.op2.as_ref().unwrap(), &op2, pc);
             let val3 = expand_op(values.op3.as_ref().unwrap(), &op3, pc);
             format!("{} {}, {}, {}", mnemonic, val1, val2, val3)
         }
         _ => format!("")
     }
}
