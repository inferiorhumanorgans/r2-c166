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

use std::convert::TryFrom;
use std::str::FromStr;
use num_traits::FromPrimitive;
use std::fmt;

use ::r2::_RAnalOpType;
use ::encoding::EncodingType;
use ::reg::*;

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Primitive)]
pub enum OpCondition {
    cc_UC   = 0x00,
    cc_NET  = 0x01,
    cc_Z    = 0x02,
    cc_NZ   = 0x03,
    cc_V    = 0x04,
    cc_NV   = 0x05,
    cc_N    = 0x06,
    cc_NN   = 0x07,
    cc_C    = 0x08,
    cc_NC   = 0x09,
    cc_SGT  = 0x0A,
    cc_SLE  = 0x0B,
    cc_SLT  = 0x0C,
    cc_SGE  = 0x0D,
    cc_UGT  = 0x0E,
    cc_ULE  = 0x0F
}

impl<'a> FromStr for OpCondition {
    type Err = ();

    fn from_str(s: &str) -> Result<OpCondition, ()> {
        let mnem = String::from(s).to_uppercase();
        match mnem.as_str() {
            "CC_UC"     => Ok(OpCondition::cc_UC),
            "CC_NET"    => Ok(OpCondition::cc_NET),
            "CC_Z"      => Ok(OpCondition::cc_Z),
            "CC_NZ"     => Ok(OpCondition::cc_NZ),
            "CC_V"      => Ok(OpCondition::cc_V),
            "CC_NV"     => Ok(OpCondition::cc_NV),
            "CC_N"      => Ok(OpCondition::cc_N),
            "CC_NN"     => Ok(OpCondition::cc_NN),
            "CC_C"      => Ok(OpCondition::cc_C),
            "CC_NC"     => Ok(OpCondition::cc_NC),
            "CC_SGT"    => Ok(OpCondition::cc_SGT),
            "CC_SLE"    => Ok(OpCondition::cc_SLE),
            "CC_SLT"    => Ok(OpCondition::cc_SLT),
            "CC_SGE"    => Ok(OpCondition::cc_SGE),
            "CC_UGT"    => Ok(OpCondition::cc_UGT),
            "CC_ULE"    => Ok(OpCondition::cc_ULE),
            _           => Err(())
        }
    }
}


impl TryFrom<u8> for OpCondition {
    type Error = &'static str;

    fn try_from(byte: u8) -> Result<OpCondition, &'static str> {
        match OpCondition::from_u8(byte) {
            Some(condition) => Ok(condition),
            None => Err("Condition must be 0x00..=0x0F")
        }
    }
}

impl fmt::Display for OpCondition {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            _ => {
                write!(f, "{:?}", self)
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum OperandType {
    Condition,

    ByteRegister(u8),
    WordRegister(u8),

    ExtendedRegister, // Don't use me directly

    DirectMemory16,
    DirectCaddr16,
    DirectSegment8,
    DirectRelative8S,

    Indirect(u8),
    IndirectPostIncrement(u8),
    IndirectPreDecrement(u8),
    IndirectAndImmediate(u8),

    BitAddr(u8),
    BitOffset(u8),

    ImmediateData3,
    ImmediateData4,
    ImmediateData8,
    ImmediateData16,
    ImmediateMask8,
    ImmediateTrap7,
    ImmediatePage10,
    ImmediateSegment8,
    ImmediateIrange2
}

#[derive(Clone, Copy, Debug)]
pub enum Operand {
    Condition(OpCondition),
    BitAddr(u8, u8),
    Register(Reg),                  // SFR, ESFR, GPR
    Direct(u16, u8),                // mem, caddr, seg, rel
    Indirect(Reg),                  // [GPR],
    IndirectPostIncrement(Reg),     // [GPR+]
    IndirectPreDecrement(Reg),      // [-GPR]
    IndirectAndImmediate(Reg, u16), // [GPR+DATA16],
    Immediate(u16, u8),             // data, bitwidth; #data3, #data4, #data8, #data16, #mask8, #trap7, #pag10, #seg8, #irang2
}

#[derive(Default, Debug)]
pub struct InstructionArguments {
    pub op1: Option<Operand>,
    pub op2: Option<Operand>,
    pub op3: Option<Operand>,

    pub mnemonic : Option<String>,
    pub sub_op : Option<u8>,
}

#[derive(Debug)]
pub struct Instruction<'a> {
    pub id: u8,
    pub mnemonic: &'static str,
    pub encoding: EncodingType,
    pub r2_op_type: _RAnalOpType,
    pub esil: &'a str,
    pub op1: Option<OperandType>,
    pub op2: Option<OperandType>,
    pub op3: Option<OperandType>,
}

impl<'a> TryFrom<u8> for Instruction<'a> {
    type Error = &'a str;

    fn try_from(byte: u8) -> Result<Instruction<'a>, &'a str> {
        match byte {
            // ADD: Integer Addition
            // Performs a 2's complement binary addition of the source operand specified by op2 and the
            // destination operand specified by op1. The sum is then stored in op1.
            // E: Set if the value of op2 represents the lowest possible negative number. Cleared otherwise. Used to signal the end of a table.
            // Z: Set if result equals zero. Cleared otherwise.
            // V: Set if an arithmetic overflow occurred, i.e. the result cannot be represented in the specified data type. Cleared otherwise.
            // C: Set if a carry is generated from the most significant bit of the specified data type. Cleared otherwise.
            // N: Set if the most significant bit of the result is set. Cleared otherwise.

            0x00 => {
                Ok(Instruction {
                    // Rwn, Rwm
                    // Add direct word GPR to direct GPR
                    id: 0x00,
                    mnemonic: "add",
                    encoding: EncodingType::reg4_reg4,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: Some(OperandType::WordRegister(1)),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_ADD | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            0x02 => {
                Ok(Instruction {
                    // reg, mem
                    // Add direct word memory to direct register
                    id: 0x02,
                    mnemonic: "add",
                    encoding: EncodingType::reg8_mem16,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: Some(OperandType::DirectMemory16),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_ADD | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            0x04 => {
                Ok(Instruction {
                    // mem, reg
                    // Add direct word register to direct memory
                    id: 0x04,
                    mnemonic: "add",
                    encoding: EncodingType::reg8_mem16,
                    op1: Some(OperandType::DirectMemory16),
                    op2: Some(OperandType::WordRegister(0)),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_ADD | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            0x06 => {
                Ok(Instruction {
                    // reg, #data16
                    // Add immediate word data to direct register
                    id: 0x06,
                    mnemonic: "add",
                    encoding: EncodingType::reg8_data16,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: Some(OperandType::ImmediateData16),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_ADD | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            0x08 => {
                Ok(Instruction {
                    // Rwn, [Rwi]
                    // Add indirect word memory to direct GPR
                    // Rwn, [Rwi+]
                    // Add indirect word memory to direct GPR and post-increment source pointer by 2
                    // Rwn, #data3
                    // Add immediate word data to direct GPR
                    id: 0x08,
                    mnemonic: "add",
                    encoding: EncodingType::reg4_or_data3,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: Some(OperandType::ImmediateData3),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_ADD,
                    esil: "",
                })
            },

            // ADDB: Integer Addition
            // Performs a 2's complement binary addition of the source operand specified by op2 and the destination
            // operand specified by op1. The sum is then stored in op1.
            // E: Set if the value of op2 represents the lowest possible negative number. Cleared otherwise. Used to signal the end of a table.
            // Z: Set if result equals zero. Cleared otherwise.
            // V: Set if an arithmetic overflow occurred, i.e. the result cannot be represented in the specified data type. Cleared otherwise.
            // C: Set if a carry is generated from the most significant bit of the specified data type. Cleared otherwise.
            // N: Set if the most significant bit of the result is set. Cleared otherwise.

            0x01 => {
                Ok(Instruction {
                    // Rbn, Rbm
                    // Add direct byte GPR to direct GPR
                    id: 0x01,
                    mnemonic: "addb",
                    encoding: EncodingType::reg4_reg4,
                    op1: Some(OperandType::ByteRegister(0)),
                    op2: Some(OperandType::ByteRegister(1)),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_ADD | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            0x03 => {
                Ok(Instruction {
                    // reg, mem
                    // Add direct byte memory to direct register
                    id: 0x03,
                    mnemonic: "addb",
                    encoding: EncodingType::reg8_mem16,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: Some(OperandType::DirectMemory16),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_ADD | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            0x05 => {
                Ok(Instruction {
                    // mem, reg
                    // Add direct byte register to direct memory
                    id: 0x05,
                    mnemonic: "addb",
                    encoding: EncodingType::reg8_mem16,
                    op1: Some(OperandType::DirectMemory16),
                    op2: Some(OperandType::WordRegister(0)),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_ADD | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            0x07 => {
                Ok(Instruction {
                    // reg, #data8
                    // Add immediate byte data to direct register
                    id: 0x07,
                    mnemonic: "addb",
                    encoding: EncodingType::reg8_data8_nop8,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: Some(OperandType::ImmediateData8),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_ADD | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            0x09 => {
                Ok(Instruction {
                    // Rbn, [Rwi]
                    // Add indirect byte memory to direct GPR
                    // Rbn, [Rwi+]
                    // Add indirect byte memory to direct GPR and post-increment source pointer by 1
                    // Rbn, #data3
                    // Add immediate byte data to direct GPR
                    id: 0x09,
                    mnemonic: "addb",
                    encoding: EncodingType::reg4_or_data3,
                    op1: Some(OperandType::ByteRegister(0)),
                    op2: Some(OperandType::ImmediateData3),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_ADD,
                    esil: "",
                })
            },

            // ADDC: Integer Addition with Carry
            // Performs a 2's complement binary addition of the source operand specified by op2, the destination
            // operand specified by op1 and the previously generated carry bit. The sum is then stored in op1.
            // This instruction can be used to perform multiple precision arithmetic.
            // E: Set if the value of op2 represents the lowest possible negative number. Cleared otherwise. Used to signal the end of a table.
            // Z: Set if result equals zero and the previous Z flag was set. Cleared otherwise.
            // V: Set if an arithmetic overflow occurred, i.e. the result cannot be represented in the specified data type. Cleared otherwise.
            // C: Set if a carry is generated from the most significant bit of the specified data type. Cleared otherwise.
            // N: Set if the most significant bit of the result is set. Cleared otherwise.

            0x10 => {
                Ok(Instruction {
                    // Rwn, Rwm
                    // Add direct word GPR to direct GPR with Carry
                    id: 0x10,
                    mnemonic: "addc",
                    encoding: EncodingType::reg4_reg4,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: Some(OperandType::WordRegister(1)),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_ADD | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            0x18 => {
                Ok(Instruction {
                    // Rwn, [Rwi]
                    // Add indirect word memory to direct GPR with Carry
                    // Rwn, [Rwi+]
                    // Add indirect word memory to direct GPR with Carry and post-increment source pointer by 2
                    // Rwn, #data3
                    // Add immediate word data to direct GPR with Carry
                    id: 0x18,
                    mnemonic: "addc",
                    encoding: EncodingType::reg4_or_data3,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: Some(OperandType::ImmediateData3),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_ADD,
                    esil: "",
                })
            },

            0x16 => {
                Ok(Instruction {
                    // reg, #data16
                    // Add immediate word data to direct register with Carry
                    id: 0x16,
                    mnemonic: "addc",
                    encoding: EncodingType::reg8_data16,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: Some(OperandType::ImmediateData16),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_ADD | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            0x12 => {
                Ok(Instruction {
                    // reg, mem
                    // Add direct word memory to direct register with Carry
                    id: 0x12,
                    mnemonic: "addc",
                    encoding: EncodingType::reg8_mem16,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: Some(OperandType::DirectMemory16),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_ADD | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            0x14 => {
                Ok(Instruction {
                    // mem, reg
                    // Add direct word register to direct memory with Carry
                    id: 0x14,
                    mnemonic: "addc",
                    encoding: EncodingType::reg8_mem16,
                    op1: Some(OperandType::DirectMemory16),
                    op2: Some(OperandType::WordRegister(0)),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_ADD | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            // ADDCB: Integer Addition with Carry
            // Performs a 2's complement binary addition of the source operand specified by op2, the destination
            // operand specified by op1 and the previously generated carry bit. The sum is then stored in op1. This
            // instruction can be used to perform multiple precision arithmetic.
            // E: Set if the value of op2 represents the lowest possible negative number. Cleared otherwise. Used to signal the end of a table.
            // Z: Set if result equals zero and the previous Z flag was set. Cleared otherwise.
            // V: Set if an arithmetic overflow occurred, i.e. the result cannot be represented in the specified data type. Cleared otherwise.
            // C: Set if a carry is generated from the most significant bit of the specified data type. Cleared otherwise.
            // N: Set if the most significant bit of the result is set. Cleared otherwise.

            0x11 => {
                Ok(Instruction {
                    // Rbn, Rbm
                    // Add direct byte GPR to direct GPR with Carry
                    id: 0x11,
                    mnemonic: "addcb",
                    encoding: EncodingType::reg4_reg4,
                    op1: Some(OperandType::ByteRegister(0)),
                    op2: Some(OperandType::ByteRegister(1)),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_ADD | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            0x19 => {
                Ok(Instruction {
                    // Rbn, [Rwi]
                    // Add indirect byte memory to direct GPR with Carry
                    // Rbn, [Rwi+]
                    // Add indirect byte memory to direct GPR with Carry and post-increment source pointer by 1
                    // Rbn, #data3
                    // Add immediate byte data to direct GPR with Carry
                    id: 0x19,
                    mnemonic: "addcb",
                    encoding: EncodingType::reg4_or_data3,
                    op1: Some(OperandType::ByteRegister(0)),
                    op2: Some(OperandType::ImmediateData3),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_ADD,
                    esil: "",
                })
            },

            0x17 => {
                Ok(Instruction {
                    // reg, #data8
                    // Add immediate byte data to direct register with Carry
                    id: 0x17,
                    mnemonic: "addcb",
                    encoding: EncodingType::reg8_data8_nop8,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: Some(OperandType::ImmediateData8),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_ADD | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            0x13 => {
                Ok(Instruction {
                    // reg, mem
                    // Add direct byte memory to direct register with Carry
                    id: 0x13,
                    mnemonic: "addcb",
                    encoding: EncodingType::reg8_mem16,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: Some(OperandType::DirectMemory16),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_ADD | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            0x15 => {
                Ok(Instruction {
                    // mem, reg
                    // Add direct byte register to direct memory with Carry
                    id: 0x15,
                    mnemonic: "addcb",
                    encoding: EncodingType::reg8_mem16,
                    op1: Some(OperandType::DirectMemory16),
                    op2: Some(OperandType::WordRegister(0)),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_ADD | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            // AND: Logical AND
            // (op1) ← (op1) ∧ (op2)
            // Performs a bitwise logical AND of the source operand specified by op2 and the destination operand
            // specified by op1. The result is then stored in op1.
            // E: Set if the value of op2 represents the lowest possible negative number. Cleared otherwise. Used to signal the end of a table.
            // Z: Set if result equals zero. Cleared otherwise.
            // V: Always cleared.
            // C: Always cleared.
            // N: Set if the most significant bit of the result is set. Cleared otherwise.

            0x60 => {
                Ok(Instruction {
                    // Rwn, Rwm
                    // Bitwise AND direct word GPR with direct GPR
                    id: 0x60,
                    mnemonic: "and",
                    encoding: EncodingType::reg4_reg4,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: Some(OperandType::WordRegister(1)),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_AND | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "{op2},NUM,{op1},&=",
                })
            },

            0x68 => {
                Ok(Instruction {
                    // Rwn, [Rwi]
                    // Bitwise AND indirect word memory with direct GPR
                    // Rwn, [Rwi+]
                    // Bitwise AND indirect word memory with direct GPR and post-increment source pointer by 2
                    // Rwn, #data3
                    // Bitwise AND immediate word data with direct GPR
                    id: 0x68,
                    mnemonic: "and",
                    encoding: EncodingType::reg4_or_data3,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: Some(OperandType::ImmediateData3),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_AND,
                    esil: "",
                })
            },

            0x66 => {
                Ok(Instruction {
                    // reg, #data16
                    // Bitwise AND immediate word data with direct register
                    id: 0x66,
                    mnemonic: "and",
                    encoding: EncodingType::reg8_data16,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: Some(OperandType::ImmediateData16),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_AND | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "{op2},{op1},&=",
                })
            },

            0x62 => {
                Ok(Instruction {
                    // reg, mem
                    // Bitwise AND direct word memory with direct register
                    id: 0x62,
                    mnemonic: "and",
                    encoding: EncodingType::reg8_mem16,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: Some(OperandType::DirectMemory16),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_AND | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            0x64 => {
                Ok(Instruction {
                    // mem, reg
                    // Bitwise AND direct word register with direct memory
                    id: 0x64,
                    mnemonic: "and",
                    encoding: EncodingType::reg8_mem16,
                    op1: Some(OperandType::DirectMemory16),
                    op2: Some(OperandType::WordRegister(0)),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_AND | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            // ANDB: Logical AND
            // Performs a bitwise logical AND of the source operand specified by op2 and the destination operand specified by op1.
            // The result is then stored in op1.
            // E: Set if the value of op2 represents the lowest possible negative number. Cleared otherwise. Used to signal the end of a table.
            // Z: Set if result equals zero. Cleared otherwise.
            // V: Always cleared.
            // C: Always cleared.
            // N: Set if the most significant bit of the result is set. Cleared otherwise.

            0x61 => {
                Ok(Instruction {
                    // Rbn, Rbm
                    // Bitwise AND direct byte GPR with direct byte GPR
                    id: 0x61,
                    mnemonic: "andb",
                    encoding: EncodingType::reg4_reg4,
                    op1: Some(OperandType::ByteRegister(0)),
                    op2: Some(OperandType::ByteRegister(1)),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_AND | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            0x69 => {
                Ok(Instruction {
                    // Rbn, [Rwi]
                    // Bitwise AND indirect byte memory with direct GPR
                    // Rbn, [Rwi+]
                    // Bitwise AND indirect byte memory with direct GPR and post-increment source pointer by 1
                    // Rbn, #data3
                    // Bitwise AND immediate byte data with direct GPR
                    id: 0x69,
                    mnemonic: "andb",
                    encoding: EncodingType::reg4_or_data3,
                    op1: Some(OperandType::ByteRegister(0)),
                    op2: Some(OperandType::ImmediateData3),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_AND,
                    esil: "",
                })
            },

            0x67 => {
                Ok(Instruction {
                    // reg, #data8
                    // Bitwise AND immediate byte data with direct register
                    id: 0x67,
                    mnemonic: "andb",
                    encoding: EncodingType::reg8_data8_nop8,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: Some(OperandType::ImmediateData8),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_AND | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            0x63 => {
                Ok(Instruction {
                    // reg, mem
                    // Bitwise AND direct byte memory with direct register
                    id: 0x63,
                    mnemonic: "andb",
                    encoding: EncodingType::reg8_mem16,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: Some(OperandType::DirectMemory16),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_AND | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            0x65 => {
                Ok(Instruction {
                    // mem, reg
                    // Bitwise AND direct byte register with direct memory
                    id: 0x65,
                    mnemonic: "andb",
                    encoding: EncodingType::reg8_mem16,
                    op1: Some(OperandType::DirectMemory16),
                    op2: Some(OperandType::WordRegister(0)),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_AND | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            // ASHR: Arithmetic Shift Right
            // Arithmetically shifts the destination word operand op1 right by as many times as specified in the source
            // operand op2. To preserve the sign of the original operand op1, the most significant bits of the result are
            // filled with zeros if the original MSB was a 0 or with ones if the original MSB was a 1. The Overflow flag is
            // used as a Rounding flag. The LSB is shifted into the Carry. Only shift values between 0 and 15 are allowed.
            // When using a GPR as the count control, only the least significant 4 bits are used.
            // E: Always cleared.
            // Z: Set if result equals zero. Cleared otherwise.
            // V: Set if in any cycle of the shift operation a 1 is shifted out of the carry flag. Cleared for a shift count of zero.
            // C: The carry flag is set according to the last LSB shifted out of op1. Cleared for a shift count of zero.
            // N: Set if the most significant bit of the result is set. Cleared otherwise.

            0xAC => {
                Ok(Instruction {
                    // Rwn, Rwm
                    // Arithmetic (sign bit) shift right direct word GPR; number of shift cycles specified by direct GPR
                    id: 0xAC,
                    mnemonic: "ashr",
                    encoding: EncodingType::reg4_reg4,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: Some(OperandType::WordRegister(1)),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_SHR | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            0xBC => {
                Ok(Instruction {
                    // Rwn, #data4
                    // Arithmetic (sign bit) shift right direct word GPR; number of shift cycles specified by immediate data
                    id: 0xBC,
                    mnemonic: "ashr",
                    encoding: EncodingType::reg4_data4,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: Some(OperandType::ImmediateData4),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_SHR | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            // ATOMIC: Begin ATOMIC Sequence
            // Causes standard and PEC interrupts and class A hardware traps to be disabled for a specified number of
            // instructions. The ATOMIC instruction becomes immediately active such that no additional NOPs are required.
            // Depending on the value of op1, the period of validity of the ATOMIC sequence extends over the sequence of the
            // next 1 to 4 instructions being executed after the ATOMIC instruction. All instructions requiring multiple
            // cycles or hold states to be executed are regarded as one instruction in this sense. Any instruction type can
            // be used with the ATOMIC instruction.
            //
            // NOTE: The ATOMIC instruction is not available in the SAB 8XC166(W)
            // NOTE: Condition flags not affected

            // EXTR: Begin EXTended Register Sequence
            // Causes all SFR or SFR bit accesses via the 'reg', 'bitoff' or 'bitaddr' addressing modes being made to the
            // Extended SFR space for a specified number of instructions. During their execution both standard/PEC interrupts
            // and class A hardware traps are locked. The value of op1 defines the length of the effected instruction sequence.
            //
            // NOTE: The EXTR instruction is not available in the SAB 8XC166(W)
            // NOTE: Condition flags not affected

            0xD1 => {
                Ok(Instruction {
                    // #irang2
                    // Begin ATOMIC sequence

                    // #irang2
                    // Begin EXTended Register sequence
                    id: 0xD1,
                    mnemonic: "atomic_extr",
                    encoding: EncodingType::op_d1,
                    op1: Some(OperandType::ImmediateIrange2),
                    op2: None,
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_NULL,
                    esil: "",
                })
            },

            // BAND: Bit Logical AND
            // Performs a single bit logical AND of the source bit specified by op2 and the destination
            // bit specified by op1. The result is then stored in op1.
            // E: Always cleared.
            // Z: Contains the logical NOR of the two specified bits.
            // V: Contains the logical OR of the two specified bits.
            // C: Contains the logical AND of the two specified bits.
            // N: Contains the logical XOR of the two specified bits.

            0x6A => {
                Ok(Instruction {
                    // bitaddrZ.z, bitaddrQ.q
                    // AND direct bit with direct bit
                    id: 0x6A,
                    mnemonic: "band",
                    encoding: EncodingType::bitaddr8_bitaddr8_bit4_bit4,
                    op1: Some(OperandType::BitAddr(1)),
                    op2: Some(OperandType::BitAddr(0)),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_AND,
                    esil: "",
                })
            },

            // BCLR: Bit Clear
            // Clears the bit specified by op1. This instruction is primarily used for peripheral and system control.
            // E: Always cleared.
            // Z: Contains the logical negation of the previous state of the specified bit.
            // V: Always cleared.
            // C: Always cleared.
            // N: Contains the previous state of the specified bit.

            0x0E => {
                Ok(Instruction {
                    // bitaddrQ.q
                    // Clear direct bit
                    id: 0x0E,
                    mnemonic: "bclr",
                    encoding: EncodingType::bitopcode4_e_bitaddr8,
                    op1: Some(OperandType::BitAddr(0)),
                    op2: None,
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_AND,
                    esil: "",
                })
            },

            0x1E => {
                Ok(Instruction {
                    // bitaddrQ.q
                    // Clear direct bit
                    id: 0x1E,
                    mnemonic: "bclr",
                    encoding: EncodingType::bitopcode4_e_bitaddr8,
                    op1: Some(OperandType::BitAddr(0)),
                    op2: None,
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_AND,
                    esil: "",
                })
            },

            0x2E => {
                Ok(Instruction {
                    // bitaddrQ.q
                    // Clear direct bit
                    id: 0x2E,
                    mnemonic: "bclr",
                    encoding: EncodingType::bitopcode4_e_bitaddr8,
                    op1: Some(OperandType::BitAddr(0)),
                    op2: None,
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_AND,
                    esil: "",
                })
            },

            0x3E => {
                Ok(Instruction {
                    // bitaddrQ.q
                    // Clear direct bit
                    id: 0x3E,
                    mnemonic: "bclr",
                    encoding: EncodingType::bitopcode4_e_bitaddr8,
                    op1: Some(OperandType::BitAddr(0)),
                    op2: None,
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_AND,
                    esil: "",
                })
            },

            0x4E => {
                Ok(Instruction {
                    // bitaddrQ.q
                    // Clear direct bit
                    id: 0x4E,
                    mnemonic: "bclr",
                    encoding: EncodingType::bitopcode4_e_bitaddr8,
                    op1: Some(OperandType::BitAddr(0)),
                    op2: None,
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_AND,
                    esil: "",
                })
            },

            0x5E => {
                Ok(Instruction {
                    // bitaddrQ.q
                    // Clear direct bit
                    id: 0x5E,
                    mnemonic: "bclr",
                    encoding: EncodingType::bitopcode4_e_bitaddr8,
                    op1: Some(OperandType::BitAddr(0)),
                    op2: None,
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_AND,
                    esil: "",
                })
            },

            0x6E => {
                Ok(Instruction {
                    // bitaddrQ.q
                    // Clear direct bit
                    id: 0x6E,
                    mnemonic: "bclr",
                    encoding: EncodingType::bitopcode4_e_bitaddr8,
                    op1: Some(OperandType::BitAddr(0)),
                    op2: None,
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_AND,
                    esil: "",
                })
            },

            0x7E => {
                Ok(Instruction {
                    // bitaddrQ.q
                    // Clear direct bit
                    id: 0x7E,
                    mnemonic: "bclr",
                    encoding: EncodingType::bitopcode4_e_bitaddr8,
                    op1: Some(OperandType::BitAddr(0)),
                    op2: None,
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_AND,
                    esil: "",
                })
            },

            0x8E => {
                Ok(Instruction {
                    // bitaddrQ.q
                    // Clear direct bit
                    id: 0x8E,
                    mnemonic: "bclr",
                    encoding: EncodingType::bitopcode4_e_bitaddr8,
                    op1: Some(OperandType::BitAddr(0)),
                    op2: None,
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_AND,
                    esil: "",
                })
            },

            0x9E => {
                Ok(Instruction {
                    // bitaddrQ.q
                    // Clear direct bit
                    id: 0x9E,
                    mnemonic: "bclr",
                    encoding: EncodingType::bitopcode4_e_bitaddr8,
                    op1: Some(OperandType::BitAddr(0)),
                    op2: None,
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_AND,
                    esil: "",
                })
            },

            0xAE => {
                Ok(Instruction {
                    // bitaddrQ.q
                    // Clear direct bit
                    id: 0xAE,
                    mnemonic: "bclr",
                    encoding: EncodingType::bitopcode4_e_bitaddr8,
                    op1: Some(OperandType::BitAddr(0)),
                    op2: None,
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_AND,
                    esil: "",
                })
            },

            0xBE => {
                Ok(Instruction {
                    // bitaddrQ.q
                    // Clear direct bit
                    id: 0xBE,
                    mnemonic: "bclr",
                    encoding: EncodingType::bitopcode4_e_bitaddr8,
                    op1: Some(OperandType::BitAddr(0)),
                    op2: None,
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_AND,
                    esil: "",
                })
            },

            0xCE => {
                Ok(Instruction {
                    // bitaddrQ.q
                    // Clear direct bit
                    id: 0xCE,
                    mnemonic: "bclr",
                    encoding: EncodingType::bitopcode4_e_bitaddr8,
                    op1: Some(OperandType::BitAddr(0)),
                    op2: None,
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_AND,
                    esil: "",
                })
            },

            0xDE => {
                Ok(Instruction {
                    // bitaddrQ.q
                    // Clear direct bit
                    id: 0xDE,
                    mnemonic: "bclr",
                    encoding: EncodingType::bitopcode4_e_bitaddr8,
                    op1: Some(OperandType::BitAddr(0)),
                    op2: None,
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_AND,
                    esil: "",
                })
            },

            0xEE => {
                Ok(Instruction {
                    // bitaddrQ.q
                    // Clear direct bit
                    id: 0xEE,
                    mnemonic: "bclr",
                    encoding: EncodingType::bitopcode4_e_bitaddr8,
                    op1: Some(OperandType::BitAddr(0)),
                    op2: None,
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_AND,
                    esil: "",
                })
            },

            0xFE => {
                Ok(Instruction {
                    // bitaddrQ.q
                    // Clear direct bit
                    id: 0xFE,
                    mnemonic: "bclr",
                    encoding: EncodingType::bitopcode4_e_bitaddr8,
                    op1: Some(OperandType::BitAddr(0)),
                    op2: None,
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_AND,
                    esil: "",
                })
            },

            // BCMP: Bit to Bit Compare
            // Performs a single bit comparison of the source bit specified by operand op1 to the source bit
            // specified by operand op2. No result is written by this instruction. Only the condition codes
            // are updated.
            // E: Always cleared.
            // Z: Contains the logical NOR of the two specified bits.
            // V: Contains the logical OR of the two specified bits.
            // C: Contains the logical AND of the two specified bits.
            // N: Contains the logical XOR of the two specified bits.

            0x2A => {
                Ok(Instruction {
                    // bitaddrZ.z, bitaddrQ.q
                    // Compare direct bit to direct bit
                    id: 0x2A,
                    mnemonic: "bcmp",
                    encoding: EncodingType::bitaddr8_bitaddr8_bit4_bit4,
                    op1: Some(OperandType::BitAddr(1)),
                    op2: Some(OperandType::BitAddr(0)),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CMP,
                    esil: "",
                })
            },

            // BFLDH: Bit Field High Byte
            // Replaces those bits in the high byte of the destination word operand op1 which are selected by
            // a '1' in the AND mask op2 with the bits at the corresponding positions in the OR mask specified
            // by op3.
            //
            // NOTE: op1 bits which shall remain unchanged must have a '0' in the respective bit of both the AND
            // mask op2 and the OR mask op3.  Otherwise a '1' in op3 will set the corresponding op1 bit
            // (see "Operation"). If the target operand (op1) features bit-protection only the bits marked by a
            // '1' in the mask operand (op2) will be updated.
            // E: Always cleared.
            // Z: Set if the word result equals zero. Cleared otherwise.
            // V: Always cleared.
            // C: Always cleared.
            // N: Set if the most significant bit of the word result is set. Cleared otherwise.

            0x1A => {
                Ok(Instruction {
                    // bitoffQ, #mask8, #data8
                    // Bitwise modify masked high byte of bit-addressable direct word memory with immediate data
                    id: 0x1A,
                    mnemonic: "bfldh",
                    encoding: EncodingType::bitoff8_mask8_data8,
                    op1: Some(OperandType::BitOffset(0)),
                    op2: Some(OperandType::ImmediateMask8),
                    op3: Some(OperandType::ImmediateData8),
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_NULL,
                    esil: "",
                })
            },

            // BFLDL: Bit Field Low Byte
            // Replaces those bits in the low byte of the destination word operand op1 which are selected by
            // a '1' in the AND mask op2 with the bits at the corresponding positions in the OR mask specified
            // by op3.
            //
            // NOTE: op1 bits which shall remain unchanged must have a '0' in the respective bit of both the AND
            // mask op2 and the OR mask op3.  Otherwise a '1' in op3 will set the corresponding op1 bit
            // (see "Operation"). If the target operand (op1) features bit-protection only the bits marked by a
            // '1' in the mask operand (op2) will be updated.
            // E: Always cleared.
            // Z: Set if the word result equals zero. Cleared otherwise.
            // V: Always cleared.
            // C: Always cleared.
            // N: Set if the most significant bit of the word result is set. Cleared otherwise.

            0x0A => {
                Ok(Instruction {
                    // bitoffQ,#mask8,#data8
                    // Bitwise modify masked low byte of bit-addressable direct word memory with immediate data
                    id: 0x0A,
                    mnemonic: "bfldl",
                    encoding: EncodingType::bitoff8_mask8_data8,
                    op1: Some(OperandType::BitOffset(0)),
                    op2: Some(OperandType::ImmediateMask8),
                    op3: Some(OperandType::ImmediateData8),
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_NULL,
                    esil: "",
                })
            },

            // BMOV: Bit to Bit Move
            // Moves a single bit from the source operand specified by op2 into the destination operand specified
            // by op1. The source bit is examined and the flags are updated accordingly.
            // E: Always cleared.
            // Z: Contains the logical negation of the previous state of the source bit.
            // V: Always cleared.
            // C: Always cleared.
            // N: Contains the previous state of the source bit.

            0x4A => {
                Ok(Instruction {
                    // bitaddrZ.z, bitaddrQ.q
                    // Move direct bit to direct bit
                    id: 0x4A,
                    mnemonic: "bmov",
                    encoding: EncodingType::bitaddr8_bitaddr8_bit4_bit4,
                    op1: Some(OperandType::BitAddr(1)),
                    op2: Some(OperandType::BitAddr(0)),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV,
                    esil: "",
                })
            },

            // BMOVN: Bit to Bit Move and Negate
            // Moves the complement of a single bit from the source operand specified by op2 into the destination
            // operand specified by op1. The source bit is examined and the flags are updated accordingly.
            // E: Always cleared.
            // Z: Contains the logical negation of the previous state of the source bit.
            // V: Always cleared.
            // C: Always cleared.
            // N: Contains the previous state of the source bit.

            0x3A => {
                Ok(Instruction {
                    // bitaddrZ.z, bitaddrQ.q
                    // Move negated direct bit to direct bit
                    id: 0x3A,
                    mnemonic: "bmovn",
                    encoding: EncodingType::bitaddr8_bitaddr8_bit4_bit4,
                    op1: Some(OperandType::BitAddr(1)),
                    op2: Some(OperandType::BitAddr(0)),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV,
                    esil: "",
                })
            },

            // BOR: Bit Logical OR
            // Performs a single bit logical OR of the source bit specified by operand op2 with the destination
            // bit specified by operand op1. The ORed result is then stored in op1.
            // E: Always cleared.
            // Z: Contains the logical NOR of the two specified bits.
            // V: Contains the logical OR of the two specified bits.
            // C: Contains the logical AND of the two specified bits.
            // N: Contains the logical XOR of the two specified bits.

            0x5A => {
                Ok(Instruction {
                    // bitaddrZ.z, bitaddrQ.q
                    // OR direct bit with direct bit
                    id: 0x5A,
                    mnemonic: "bor",
                    encoding: EncodingType::bitaddr8_bitaddr8_bit4_bit4,
                    op1: Some(OperandType::BitAddr(1)),
                    op2: Some(OperandType::BitAddr(0)),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_OR,
                    esil: "",
                })
            },

            // BSET: Bit Set
            // Sets the bit specified by op1. This instruction is primarily used for peripheral and system control.
            // E: Always cleared.
            // Z: Contains the logical negation of the previous state of the specified bit
            // V: Always cleared.
            // C: Always cleared.
            // N: Contains the previous state of the specified bit.

            0x0F => {
                Ok(Instruction {
                    // bitaddrQ.q
                    // Set direct bit
                    id: 0x0F,
                    mnemonic: "bset",
                    encoding: EncodingType::bitopcode4_f_bitaddr8,
                    op1: Some(OperandType::BitAddr(0)),
                    op2: None,
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_OR,
                    esil: "",
                })
            },

            0x1F => {
                Ok(Instruction {
                    // bitaddrQ.q
                    // Set direct bit
                    id: 0x1F,
                    mnemonic: "bset",
                    encoding: EncodingType::bitopcode4_f_bitaddr8,
                    op1: Some(OperandType::BitAddr(0)),
                    op2: None,
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_OR,
                    esil: "",
                })
            },

            0x2F => {
                Ok(Instruction {
                    // bitaddrQ.q
                    // Set direct bit
                    id: 0x2F,
                    mnemonic: "bset",
                    encoding: EncodingType::bitopcode4_f_bitaddr8,
                    op1: Some(OperandType::BitAddr(0)),
                    op2: None,
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_OR,
                    esil: "",
                })
            },

            0x3F => {
                Ok(Instruction {
                    // bitaddrQ.q
                    // Set direct bit
                    id: 0x3F,
                    mnemonic: "bset",
                    encoding: EncodingType::bitopcode4_f_bitaddr8,
                    op1: Some(OperandType::BitAddr(0)),
                    op2: None,
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_OR,
                    esil: "",
                })
            },

            0x4F => {
                Ok(Instruction {
                    // bitaddrQ.q
                    // Set direct bit
                    id: 0x4F,
                    mnemonic: "bset",
                    encoding: EncodingType::bitopcode4_f_bitaddr8,
                    op1: Some(OperandType::BitAddr(0)),
                    op2: None,
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_OR,
                    esil: "",
                })
            },

            0x5F => {
                Ok(Instruction {
                    // bitaddrQ.q
                    // Set direct bit
                    id: 0x5F,
                    mnemonic: "bset",
                    encoding: EncodingType::bitopcode4_f_bitaddr8,
                    op1: Some(OperandType::BitAddr(0)),
                    op2: None,
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_OR,
                    esil: "",
                })
            },

            0x6F => {
                Ok(Instruction {
                    // bitaddrQ.q
                    // Set direct bit
                    id: 0x6F,
                    mnemonic: "bset",
                    encoding: EncodingType::bitopcode4_f_bitaddr8,
                    op1: Some(OperandType::BitAddr(0)),
                    op2: None,
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_OR,
                    esil: "",
                })
            },

            0x7F => {
                Ok(Instruction {
                    // bitaddrQ.q
                    // Set direct bit
                    id: 0x7F,
                    mnemonic: "bset",
                    encoding: EncodingType::bitopcode4_f_bitaddr8,
                    op1: Some(OperandType::BitAddr(0)),
                    op2: None,
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_OR,
                    esil: "",
                })
            },

            0x8F => {
                Ok(Instruction {
                    // bitaddrQ.q
                    // Set direct bit
                    id: 0x8F,
                    mnemonic: "bset",
                    encoding: EncodingType::bitopcode4_f_bitaddr8,
                    op1: Some(OperandType::BitAddr(0)),
                    op2: None,
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_OR,
                    esil: "",
                })
            },

            0x9F => {
                Ok(Instruction {
                    // bitaddrQ.q
                    // Set direct bit
                    id: 0x9F,
                    mnemonic: "bset",
                    encoding: EncodingType::bitopcode4_f_bitaddr8,
                    op1: Some(OperandType::BitAddr(0)),
                    op2: None,
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_OR,
                    esil: "",
                })
            },

            0xAF => {
                Ok(Instruction {
                    // bitaddrQ.q
                    // Set direct bit
                    id: 0xAF,
                    mnemonic: "bset",
                    encoding: EncodingType::bitopcode4_f_bitaddr8,
                    op1: Some(OperandType::BitAddr(0)),
                    op2: None,
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_OR,
                    esil: "",
                })
            },

            0xBF => {
                Ok(Instruction {
                    // bitaddrQ.q
                    // Set direct bit
                    id: 0xBF,
                    mnemonic: "bset",
                    encoding: EncodingType::bitopcode4_f_bitaddr8,
                    op1: Some(OperandType::BitAddr(0)),
                    op2: None,
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_OR,
                    esil: "",
                })
            },

            0xCF => {
                Ok(Instruction {
                    // bitaddrQ.q
                    // Set direct bit
                    id: 0xCF,
                    mnemonic: "bset",
                    encoding: EncodingType::bitopcode4_f_bitaddr8,
                    op1: Some(OperandType::BitAddr(0)),
                    op2: None,
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_OR,
                    esil: "",
                })
            },

            0xDF => {
                Ok(Instruction {
                    // bitaddrQ.q
                    // Set direct bit
                    id: 0xDF,
                    mnemonic: "bset",
                    encoding: EncodingType::bitopcode4_f_bitaddr8,
                    op1: Some(OperandType::BitAddr(0)),
                    op2: None,
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_OR,
                    esil: "",
                })
            },

            0xEF => {
                Ok(Instruction {
                    // bitaddrQ.q
                    // Set direct bit
                    id: 0xEF,
                    mnemonic: "bset",
                    encoding: EncodingType::bitopcode4_f_bitaddr8,
                    op1: Some(OperandType::BitAddr(0)),
                    op2: None,
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_OR,
                    esil: "",
                })
            },

            0xFF => {
                Ok(Instruction {
                    // bitaddrQ.q
                    // Set direct bit
                    id: 0xFF,
                    mnemonic: "bset",
                    encoding: EncodingType::bitopcode4_f_bitaddr8,
                    op1: Some(OperandType::BitAddr(0)),
                    op2: None,
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_OR,
                    esil: "",
                })
            },

            // BXOR: Bit Logical XOR
            // Performs a single bit logical EXCLUSIVE OR of the source bit specified by operand op2 with the
            // destination bit specified by operand op1. The XORed result is then stored in op1.
            // E: Always cleared.
            // Z: Contains the logical NOR of the two specified bits.
            // V: Contains the logical OR of the two specified bits.
            // C: Contains the logical AND of the two specified bits.
            // N: Contains the logical XOR of the two specified bits.

            0x7A => {
                Ok(Instruction {
                    // bitaddrZ.z, bitaddrQ.q
                    // XOR direct bit with direct bit
                    id: 0x7A,
                    mnemonic: "bxor",
                    encoding: EncodingType::bitaddr8_bitaddr8_bit4_bit4,
                    op1: Some(OperandType::BitAddr(1)),
                    op2: Some(OperandType::BitAddr(0)),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_XOR,
                    esil: "",
                })
            },

            // CALLA: Call Subroutine Absolute
            // If the condition specified by op1 is met, a branch to the absolute memory location specified by
            // the second operand op2 is taken.  The value of the instruction pointer, IP, is placed onto the
            // system stack. Because the IP always points to the instruction following the branch instruction,
            // the value stored on the system stack represents the return address of the calling routine. If the
            // condition is not met, no action is taken and the next instruction is executed normally.
            //
            // NOTE: Condition flags not affected

            0xCA => {
                Ok(Instruction {
                    // cc, caddr
                    // Call absolute subroutine if condition is met
                    id: 0xCA,
                    mnemonic: "calla",
                    encoding: EncodingType::cond4_0_mem16,
                    op1: Some(OperandType::Condition),
                    op2: Some(OperandType::DirectCaddr16),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CALL,
                    esil: "",
                })
            },

            // CALLI: Call Subroutine Indirect
            // If the condition specified by op1 is met, a branch to the location specified indirectly by the second
            // operand op2 is taken. The value of the instruction pointer, IP, is placed onto the system stack. Because
            // the IP always points to the instruction following the branch instruction, the value stored on the system
            // stack represents the return address of the calling routine. If the condition is not met, no action is
            // taken and the next instruction is executed normally.
            //
            // NOTE: Condition flags not affected

            0xAB => {
                Ok(Instruction {
                    // cc, [Rwn]
                    // Call indirect subroutine if condition is met
                    id: 0xAB,
                    mnemonic: "calli",
                    encoding: EncodingType::cond4_reg4,
                    op1: Some(OperandType::Condition),
                    op2: Some(OperandType::Indirect(0)),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CALL | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            // CALLR: Call Subroutine Relative
            // A branch is taken to the location specified by the instruction pointer, IP, plus the relative displacement, op1.
            // The displacement is a two's complement number which is sign extended and counts the relative distance in words.
            // The value of the instruction pointer (IP) is placed onto the system stack. Because the IP always points to the
            // instruction following the branch instruction, the value stored on the system stack represents the return address
            // of the calling routine. The value of the IP used in the target address calculation is the address of the
            // instruction following the CALLR instruction.
            //
            // NOTE: Condition flags not affected

            0xBB => {
                Ok(Instruction {
                    // rel
                    // Call relative subroutine
                    id: 0xBB,
                    mnemonic: "callr",
                    encoding: EncodingType::rel8s,
                    op1: Some(OperandType::DirectRelative8S),
                    op2: None,
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CALL,
                    esil: "",
                })
            },

            // CALLS: Call Inter-Segment Subroutine
            // A branch is taken to the absolute location specified by op2 within the segment specified by op1. The value of the
            // instruction pointer (IP) is placed onto the system stack. Because the IP always points to the instruction following
            // the branch instruction, the value stored on the system stack represents the return address to the calling routine.
            // The previous value of the CSP is also placed on the system stack to insure correct return to the calling segment.
            //
            // NOTE: Condition flags not affected

            0xDA => {
                Ok(Instruction {
                    // seg, caddr
                    // Call absolute subroutine in any code segment
                    id: 0xDA,
                    mnemonic: "calls",
                    encoding: EncodingType::seg8_mem16,
                    op1: Some(OperandType::DirectSegment8),
                    op2: Some(OperandType::DirectCaddr16),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CALL,
                    esil: "",
                })
            },

            // CMP: Integer Compare
            // The source operand specified by op1 is compared to the source operand specified by op2 by performing a 2's
            // complement binary subtraction of op2 from op1. The flags are set according to the rules of subtraction. The
            // operands remain unchanged.
            // E: Set if the value of op2 represents the lowest possible negative number. Cleared otherwise. Used to signal the end of a table.
            // Z: Set if result equals zero. Cleared otherwise.
            // V: Set if an arithmetic underflow occurred, i.e. the result cannot be represented in the specified data type. Cleared otherwise.
            // C: Set if a borrow is generated. Cleared otherwise.
            // N: Set if the most significant bit of the result is set. Cleared otherwise.

            0x40 => {
                Ok(Instruction {
                    // Rwn, Rwm
                    // Compare direct word GPR to direct GPR
                    id: 0x40,
                    mnemonic: "cmp",
                    encoding: EncodingType::reg4_reg4,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: Some(OperandType::WordRegister(1)),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CMP | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            0x48 => {
                Ok(Instruction {
                    // Rwn, [Rwi]
                    // Compare indirect word memory to direct GPR
                    // Rwn, [Rwi+]
                    // Compare indirect word memory to direct GPR and post-increment source pointer by 2
                    // Rwn, #data3
                    // Compare immediate word data to direct GPR
                    id: 0x48,
                    mnemonic: "cmp",
                    encoding: EncodingType::reg4_or_data3,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: Some(OperandType::ImmediateData3),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CMP,
                    esil: "",
                })
            },

            0x46 => {
                Ok(Instruction {
                    // reg, #data16
                    // Compare immediate word data to direct register
                    id: 0x46,
                    mnemonic: "cmp",
                    encoding: EncodingType::reg8_data16,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: Some(OperandType::ImmediateData16),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CMP | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            0x42 => {
                Ok(Instruction {
                    // reg, mem
                    // Compare direct word memory to direct register
                    id: 0x42,
                    mnemonic: "cmp",
                    encoding: EncodingType::reg8_mem16,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: Some(OperandType::DirectMemory16),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CMP | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            // CMPB: Integer Compare
            // The source operand specified by op1 is compared to the source operand specified by op2 by performing a 2's
            // complement binary subtraction of op2 from op1. The flags are set according to the rules of subtraction. The
            // operands remain unchanged.
            // E: Set if the value of op2 represents the lowest possible negative number. Cleared otherwise. Used to signal the end of a table.
            // Z: Set if result equals zero. Cleared otherwise.
            // V: Set if an arithmetic underflow occurred, i.e. the result cannot be represented in the specified data type. Cleared otherwise.
            // C: Set if a borrow is generated. Cleared otherwise.
            // N: Set if the most significant bit of the result is set. Cleared otherwise.

            0x41 => {
                Ok(Instruction {
                    // Rbn, Rbm
                    // Compare direct byte GPR to direct GPR
                    id: 0x41,
                    mnemonic: "cmpb",
                    encoding: EncodingType::reg4_reg4,
                    op1: Some(OperandType::ByteRegister(0)),
                    op2: Some(OperandType::ByteRegister(1)),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CMP | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            0x49 => {
                Ok(Instruction {
                    // Rbn, [Rwi]
                    // Compare indirect byte memory to direct GPR
                    // Rbn, [Rwi+]
                    // Compare indirect byte memory to direct GPR and post-increment source pointer by 1
                    // Rbn, #data3
                    // Compare immediate byte data to direct GPR
                    id: 0x49,
                    mnemonic: "cmpb",
                    encoding: EncodingType::reg4_or_data3,
                    op1: Some(OperandType::ByteRegister(0)),
                    op2: Some(OperandType::ImmediateData3),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CMP,
                    esil: "",
                })
            },

            0x47 => {
                Ok(Instruction {
                    // reg, #data8
                    // Compare immediate byte data to direct register
                    id: 0x47,
                    mnemonic: "cmpb",
                    encoding: EncodingType::reg8_data8_nop8,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: Some(OperandType::ImmediateData8),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CMP | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            0x43 => {
                Ok(Instruction {
                    // reg, mem
                    // Compare direct byte memory to direct register
                    id: 0x43,
                    mnemonic: "cmpb",
                    encoding: EncodingType::reg8_mem16,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: Some(OperandType::DirectMemory16),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CMP | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            // CMPD1: Integer Compare and Decrement by 1
            // This instruction is used to enhance the performance and flexibility of loops. The source operand
            // specified by op1 is compared to the source operand specified by op2 by performing a 2's complement
            // binary subtraction of op2 from op1. Operand op1 may specify ONLY GPR registers. Once the subtraction
            // has completed, the operand op1 is decremented by one. Using the set flags, a branch instruction can
            // then be used in conjunction with this instruction to form common high level language FOR loops of
            // any range.
            // E: Set if the value of op2 represents the lowest possible negative number. Cleared otherwise. Used to signal the end of a table.
            // Z: Set if result equals zero. Cleared otherwise.
            // V: Set if an arithmetic underflow occurred, i.e. the result cannot be represented in the specified data type. Cleared otherwise.
            // C: Set if a borrow is generated. Cleared otherwise.
            // N: Set if the most significant bit of the result is set. Cleared otherwise.

            0xA0 => {
                Ok(Instruction {
                    // Rwn, #data4
                    // Compare immediate word data to direct GPR and decrement GPR by 1
                    id: 0xA0,
                    mnemonic: "cmpd1",
                    encoding: EncodingType::reg4_data4,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: Some(OperandType::ImmediateData4),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CMP | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            0xA6 => {
                Ok(Instruction {
                    // Rwn, #data16
                    // Compare immediate word data to direct GPR and decrement GPR by 1
                    id: 0xA6,
                    mnemonic: "cmpd1",
                    encoding: EncodingType::_f_reg4_data16,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: Some(OperandType::ImmediateData16),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CMP | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            0xA2 => {
                Ok(Instruction {
                    // Rwn, mem
                    // Compare direct word memory to direct GPR and decrement GPR by 1
                    id: 0xA2,
                    mnemonic: "cmpd1",
                    encoding: EncodingType::_f_reg4_mem16,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: Some(OperandType::DirectMemory16),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CMP | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            // CMPD2: Integer Compare and Decrement by 2
            // This instruction is used to enhance the performance and flexibility of loops. The source operand specified
            // by op1 is compared to the source operand specified by op2 by performing a 2's complement binary subtraction
            // of op2 from op1. Operand op1 may specify ONLY GPR registers. Once the subtraction has completed, the operand
            // op1 is decremented by two. Using the set flags, a branch instruction can then be used in conjunction with
            // this instruction to form common high level language FOR loops of any range.
            // E: Set if the value of op2 represents the lowest possible negative number. Cleared otherwise. Used to signal the end of a table.
            // Z: Set if result equals zero. Cleared otherwise.
            // V: Set if an arithmetic underflow occurred, i.e. the result cannot be represented in the specified data type. Cleared otherwise.
            // C: Set if a borrow is generated. Cleared otherwise.
            // N: Set if the most significant bit of the result is set. Cleared otherwise.

            0xB0 => {
                Ok(Instruction {
                    // Rwn, #data4
                    // Compare immediate word data to direct GPR and decrement GPR by 2
                    id: 0xB0,
                    mnemonic: "cmpd2",
                    encoding: EncodingType::reg4_data4,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: Some(OperandType::ImmediateData4),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CMP | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            0xB6 => {
                Ok(Instruction {
                    // Rwn, #data16
                    // Compare immediate word data to direct GPR and decrement GPR by 2
                    id: 0xB6,
                    mnemonic: "cmpd2",
                    encoding: EncodingType::_f_reg4_data16,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: Some(OperandType::ImmediateData16),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CMP | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            0xB2 => {
                Ok(Instruction {
                    // Rwn, mem
                    // Compare direct word memory to direct GPR and decrement GPR by 2
                    id: 0xB2,
                    mnemonic: "cmpd2",
                    encoding: EncodingType::_f_reg4_mem16,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: Some(OperandType::DirectMemory16),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CMP | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            // CMPI1: Integer Compare and Increment by 1
            // This instruction is used to enhance the performance and flexibility of loops. The source operand specified
            // by op1 is compared to the source operand specified by op2 by performing a 2's complement binary subtraction
            // of op2 from op1. Operand op1 may specify ONLY GPR registers. Once the subtraction has completed, the operand
            // op1 is incremented by one. Using the set flags, a branch instruction can then be used in conjunction with
            // this instruction to form common high level language FOR loops of any range.
            // E: Set if the value of op2 represents the lowest possible negative number. Cleared otherwise. Used to signal the end of a table.
            // Z: Set if result equals zero. Cleared otherwise.
            // V: Set if an arithmetic underflow occurred, i.e. the result cannotbe represented in the specified data type. Cleared otherwise.
            // C: Set if a borrow is generated. Cleared otherwise.
            // N: Set if the most significant bit of the result is set. Cleared otherwise.

            0x80 => {
                Ok(Instruction {
                    // Rwn, #data4
                    // Compare immediate word data to direct GPR and increment GPR by 1
                    id: 0x80,
                    mnemonic: "cmpi1",
                    encoding: EncodingType::reg4_data4,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: Some(OperandType::ImmediateData4),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CMP | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            0x86 => {
                Ok(Instruction {
                    // Rwn, #data16
                    // Compare immediate word data to direct GPR and increment GPR by 1
                    id: 0x86,
                    mnemonic: "cmpi1",
                    encoding: EncodingType::_f_reg4_data16,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: Some(OperandType::ImmediateData16),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CMP | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            0x82 => {
                Ok(Instruction {
                    // Rwn, mem
                    // Compare direct word memory to direct GPR and increment GPR by 1
                    id: 0x82,
                    mnemonic: "cmpi1",
                    encoding: EncodingType::_f_reg4_mem16,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: Some(OperandType::DirectMemory16),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CMP | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            // CMPI2: Integer Compare and Increment by 2
            // This instruction is used to enhance the performance and flexibility of loops. The source operand specified
            // by op1 is compared to the source operand specified by op2 by performing a 2's complement binary subtraction
            // of op2 from op1. Operand op1 may specify ONLY GPR registers. Once the subtraction has completed, the operand
            // op1 is incremented by two. Using the set flags, a branch instruction can then be used in conjunction with
            // this instruction to form common high level language FOR loops of any range.
            // E: Set if the value of op2 represents the lowest possible negative number. Cleared otherwise. Used to signal the end of a table.
            // Z: Set if result equals zero. Cleared otherwise.
            // V: Set if an arithmetic underflow occurred, i.e. the result cannot be represented in the specified data type. Cleared otherwise.
            // C: Set if a borrow is generated. Cleared otherwise.
            // N: Set if the most significant bit of the result is set. Cleared otherwise.

            0x90 => {
                Ok(Instruction {
                    // Rwn, #data4
                    // Compare immediate word data to direct GPR and increment GPR by 2
                    id: 0x90,
                    mnemonic: "cmpi2",
                    encoding: EncodingType::reg4_data4,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: Some(OperandType::ImmediateData4),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CMP | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            0x96 => {
                Ok(Instruction {
                    // Rwn, #data16
                    // Compare immediate word data to direct GPR and increment GPR by 2
                    id: 0x96,
                    mnemonic: "cmpi2",
                    encoding: EncodingType::_f_reg4_data16,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: Some(OperandType::ImmediateData16),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CMP | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            0x92 => {
                Ok(Instruction {
                    // Rwn, mem
                    // Compare direct word memory to direct GPR and increment GPR by 2
                    id: 0x92,
                    mnemonic: "cmpi2",
                    encoding: EncodingType::_f_reg4_mem16,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: Some(OperandType::DirectMemory16),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CMP | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            // CPL: Integer One's Complement
            // Performs a 1's complement of the source operand specified by op1. The result is stored back into op1.
            // E: Set if the value of op1 represents the lowest possible negative number. Cleared otherwise. Used to signal the end of a table.
            // Z: Set if result equals zero. Cleared otherwise.
            // V: Always cleared.
            // C: Always cleared.
            // N: Set if the most significant bit of the result is set. Cleared otherwise.

            0x91 => {
                Ok(Instruction {
                    // Rwn
                    // Complement direct word GPR
                    id: 0x91,
                    mnemonic: "cpl",
                    encoding: EncodingType::reg4_0,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: None,
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CPL | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            // CPLB: Integer One's Complement
            // Performs a 1's complement of the source operand specified by op1. The result is stored back into op1.
            // E: Set if the value of op1 represents the lowest possible negative number. Cleared otherwise. Used to signal the end of a table.
            // Z: Set if result equals zero. Cleared otherwise.
            // V: Always cleared.
            // C: Always cleared.
            // N: Set if the most significant bit of the result is set. Cleared otherwise.

            0xB1 => {
                Ok(Instruction {
                    // Rbn
                    // Complement direct byte GPR
                    id: 0xB1,
                    mnemonic: "cplb",
                    encoding: EncodingType::reg4_0,
                    op1: Some(OperandType::ByteRegister(0)),
                    op2: None,
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CPL | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            // DISWDT: Disable Watchdog Timer
            // This instruction disables the watchdog timer. The watchdog timer is enabled by a reset. The DISWDT
            // instruction allows the watchdog timer to be disabled for applications which do not require a watchdog
            // function. Following a reset, this instruction can be executed at any time until either a Service Watchdog
            // Timer instruction (SRVWDT) or an End of Initialization instruction (EINIT) are executed. Once one of these
            // instructions has been executed, the DISWDT instruction will have no effect.
            //
            // NOTE: To insure that this instruction is not accidentally executed, it is implemented as a protected instruction.
            // NOTE: Condition flags not affected

            0xA5 => {
                Ok(Instruction {
                    // ---
                    // Disable Watchdog Timer
                    id: 0xA5,
                    mnemonic: "diswdt",
                    encoding: EncodingType::NO_ARGS4,
                    op1: None,
                    op2: None,
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_NULL | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            // DIV: 16-by-16 Signed Division
            // Performs a signed 16-bit by 16-bit division of the low order word stored in the MD register by the source
            // word operand op1. The signed quotient is then stored in the low order word of the MD register (MDL) and the
            // remainder is stored in the high order word of the MD register (MDH).
            //
            // NOTE: DIV is interruptable.
            // E: Always cleared.
            // Z: Set if result equals zero. Cleared otherwise.
            // V: Set if an arithmetic overflow occurred, i.e. if the divisor (op1) was zero (the result in MDH and MDL is not valid in this case). Cleared otherwise.
            // C: Always cleared.
            // N: Set if the most significant bit of the result is set. Cleared otherwise.

            0x4B => {
                Ok(Instruction {
                    // Rwn
                    // Signed divide register MDL by direct GPR (16-bit ÷ 16-bit)
                    id: 0x4B,
                    mnemonic: "div",
                    encoding: EncodingType::reg4_dup,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: None,
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_DIV | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            // DIVL: 32-by-16 Signed Division
            // Performs an extended signed 32-bit by 16-bit division of the two words stored in the MD register by the source
            // word operand op1. The signed quotient is then stored in the low order word of the MD register (MDL) and the
            // remainder is stored in the high order word of the MD register (MDH).
            //
            // NOTE: DIVL is interruptable.
            // E: Always cleared.
            // Z: Set if result equals zero. Cleared otherwise.
            // V: Set if an arithmetic overflow occurred, i.e. the quotient cannot be represented in a word data type, or if the divisor (op1) was zero (the result in MDH and MDL is not valid in this case). Cleared otherwise.
            // C: Always cleared.
            // N: Set if the most significant bit of the result is set. Cleared otherwise.

            0x6B => {
                Ok(Instruction {
                    // Rwn
                    // Signed long divide register MD by direct GPR (32-bit ÷ 16-bit)
                    id: 0x6B,
                    mnemonic: "divl",
                    encoding: EncodingType::reg4_dup,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: None,
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_DIV | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            // DIVLU: 32-by-16 Unsigned Division
            // Performs an extended unsigned 32-bit by 16-bit division of the two words stored in the MD register by the source
            // word operand op1. The unsigned quotient is then stored in the low order word of the MD register (MDL) and the
            // remainder is stored in the high order word of the MD register (MDH).
            //
            // NOTE: DIVLU is interruptable.
            // E: Always cleared.
            // Z: Set if result equals zero. Cleared otherwise.
            // V: Set if an arithmetic overflow occurred, i.e. the quotient cannot be represented in a word data type, or if the divisor (op1) was zero (the result in MDH and MDL is not valid in this case). Cleared otherwise.
            // C: Always cleared.
            // N: Set if the most significant bit of the result is set. Cleared otherwise.

            0x7B => {
                Ok(Instruction {
                    // Rwn
                    // Unsigned long divide register MD by direct GPR (32-bit ÷ 16-bit)
                    id: 0x7B,
                    mnemonic: "divlu",
                    encoding: EncodingType::reg4_dup,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: None,
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_DIV | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            // DIVU: 16-by-16 Unsigned Division
            // Performs an unsigned 16-bit by 16-bit division of the low order word stored in the MD register by the source
            // word operand op1. The signed quotient is then stored in the low order word of the MD register (MDL) and the
            // remainder is stored in the high order word of the MD register (MDH).
            //
            // NOTE: DIVU is interruptable.
            // E: Always cleared.
            // Z: Set if result equals zero. Cleared otherwise.
            // V: Set if an arithmetic overflow occurred, i.e. if the divisor (op1) was zero (the result in MDH and MDL is not valid in this case). Cleared otherwise.
            // C: Always cleared.
            // N: Set if the most significant bit of the result is set. Cleared otherwise.

            0x5B => {
                Ok(Instruction {
                    // Rwn
                    // Unsigned divide register MDL by direct GPR (16-bit ÷ 16-bit)
                    id: 0x5B,
                    mnemonic: "divu",
                    encoding: EncodingType::reg4_dup,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: None,
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_DIV | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            // EINIT: End of Initialization
            // This instruction is used to signal the end of the initialization portion of a program. After a reset, the reset
            // output pin RSTOUT is pulled low. It remains low until the EINIT instruction has been executed at which time it
            // goes high. This enables the program to signal the external circuitry that it has successfully initialized the
            // microcontroller. After the EINIT instruction has been executed, execution of the Disable Watchdog Timer instruction
            // (DISWDT) has no effect.
            //
            // NOTE: To insure that this instruction is not accidentally executed, it is implemented as a protected instruction.
            // NOTE: Condition flags not affected
            0xB5 => {
                Ok(Instruction {
                    // ---
                    // Signify End-of-Initialization on RSTOUT-pin
                    id: 0xB5,
                    mnemonic: "einit",
                    encoding: EncodingType::NO_ARGS4,
                    op1: None,
                    op2: None,
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_NULL,
                    esil: "",
                })
            },

            // EXTP: Begin EXTended Page Sequence
            // Overrides the standard DPP addressing scheme of the long and indirect addressing modes for a specified number of
            // instructions. During their execution both standard/PEC interrupts and class A hardware traps are locked. The EXTP
            // instruction becomes immediately active such that no additional NOPs are required. For any long ('mem') or indirect
            // ([...]) address in the EXTP instruction sequence, the 10-bit page number (address bits A23 - A14) is not determined
            // by the contents of a DPP register but by the value of op1 itself. The 14-bit page offset (address bits A13 - A0) is
            // derived from the long or indirect address as usual. The value of op2 defines the length of the effected instruction
            // sequence.
            //
            // NOTE: The EXTP instruction is not available in the SAB 8XC166(W) devices.
            // NOTE: Condition flags not affected

            // EXTPR: Begin EXTended Page and Register Sequence
            // Overrides the standard DPP addressing scheme of the long and indirect addressing modes and causes all SFR or SFR bit
            // accesses via the 'reg', 'bitoff' or 'bitaddr' addressing modes being made to the Extended SFR space for a specified
            // number of instructions. During their execution both standard/PEC interrupts and class A hardware traps are locked.
            // For any long ('mem') or indirect ([...]) address in the EXTP instruction sequence, the 10-bit page number (address
            // bits A23 - A14) is not determined by the contents of a DPP register but by the value of op1 itself. The 14-bit page
            // offset (address bits A13 - A0) is derived from the long or indirect address as usual.  The value of op2 defines the
            // length of the effected instruction sequence.
            //
            // NOTE: The EXTP instruction is not available in the SAB 8XC166(W) devices.
            // NOTE: Condition flags not affected

            // EXTS: Begin EXTended Segment Sequence
            // Overrides the standard DPP addressing scheme of the long and indirect addressing modes for a specified number of
            // instructions. During their execution both standard/PEC interrupts and class A hardware traps are locked. The EXTS
            // instruction becomes immediately active such that no additional NOPs are required. For any long ('mem') or indirect
            // ([...]) address in an EXTS instruction sequence, the value of op1 determines the 8-bit segment (address bits A23 -
            // A16) valid for the corresponding data access. The long or indirect address itself represents the 16-bit segment
            // offset (address bits A15 - A0).  The value of op2 defines the length of the effected instruction sequence.
            //
            // NOTE: The EXTP instruction is not available in the SAB 8XC166(W) devices.
            // NOTE: Condition flags not affected

            // EXTSR: Begin EXTended Segment and Register Sequence
            // Overrides the standard DPP addressing scheme of the long and indirect addressing modes and causes all SFR or SFR bit
            // accesses via the 'reg', 'bitoff' or 'bitaddr' addressing modes being made to the Extended SFR space for a specified
            // number of instructions. During their execution both standard/PEC interrupts and class A hardware traps are locked.
            // The EXTSR instruction becomes immediately active such that no additional NOPs are required. For any long ('mem') or
            // indirect ([...]) address in an EXTSR instruction sequence, the value of op1 determines the 8-bit segment (address
            // bits A23 - A16) valid for the corresponding data access. The long or indirect address itself represents the 16-bit
            // segment offset (address bits A15 - A0). The value of op2 defines the length of the effected instruction sequence.
            //
            // NOTE: The EXTP instruction is not available in the SAB 8XC166(W) devices.
            // NOTE: Condition flags not affected

            0xD7 => {
                Ok(Instruction {
                    // EXTP
                    // #pag, #irang2
                    // Begin EXTended Page sequence
                    // EXTPR
                    // #pag, #irang2
                    // Begin EXTended Page and Register sequence
                    // EXTS
                    // #seg, #irang2
                    // Begin EXTended Segment sequence
                    // EXTSR
                    // #seg, #irang2
                    // Begin EXTended Segment and Register sequence
                    id: 0xD7,
                    mnemonic: "ext*",
                    encoding: EncodingType::op_d7,
                    op1: Some(OperandType::ImmediateData4),
                    op2: Some(OperandType::ImmediateIrange2),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_NULL,
                    esil: "",
                })
            },

            0xDC => {
                Ok(Instruction {
                    // EXTP
                    // Rwm, #irang2
                    // Begin EXTended Page sequence
                    // EXTPR
                    // Rwm, #irang2
                    // Begin EXTended Page and Register sequence
                    // EXTS
                    // Rwm, #irang2
                    // Begin EXTended Segment sequence
                    // EXTSR
                    // Rwm, #irang2
                    // Begin EXTended Segment and Register sequence
                    id: 0xDC,
                    mnemonic: "ext*",
                    encoding: EncodingType::op_dc,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: Some(OperandType::ImmediateIrange2),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_NULL | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            // IDLE: Enter Idle Mode
            // This instruction causes the device to enter idle mode or sleep mode (if provided by the device). In both modes the
            // CPU is powered down. In idle mode the peripherals remain running, while in sleep mode also the peripherals are powered
            // down. The device remains powered down until a peripheral interrupt (only possible in Idle mode) or an external
            // interrupt occurs.
            //
            // NOTE: Sleep mode must be selected before executing the IDLE instruction.
            // NOTE: To insure that this instruction is not accidentally executed, it is implemented as a protected instruction.
            // NOTE: Condition flags not affected

            0x87 => {
                Ok(Instruction {
                    // --
                    // Enter Idle Mode
                    id: 0x87,
                    mnemonic: "idle",
                    encoding: EncodingType::NO_ARGS4,
                    op1: None,
                    op2: None,
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_NULL,
                    esil: "",
                })
            },

            // JB: Relative Jump if Bit Set
            // If the bit specified by op1 is set, program execution continues at the location of the instruction pointer, IP, plus
            // the specified displacement, op2. The displacement is a two's complement number which is sign extended and counts the
            // relative distance in words. The value of the IP used in the target address calculation is the address of the instruction
            // following the JB instruction. If the specified bit is clear, the instruction following the JB instruction is executed.
            //
            // NOTE: Condition flags not affected

            0x8A => {
                Ok(Instruction {
                    // bitaddrQ.q, rel
                    // Jump relative if direct bit is set
                    id: 0x8A,
                    mnemonic: "jb",
                    encoding: EncodingType::bitaddr8_rel8_bit4_0,
                    op1: Some(OperandType::BitAddr(0)),
                    op2: Some(OperandType::DirectRelative8S),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_JMP | _RAnalOpType::R_ANAL_OP_TYPE_COND,
                    esil: "",
                })
            },

            // JBC: Relative Jump if Bit Set and Clear Bit
            // If the bit specified by op1 is set, program execution continues at the location of the instruction pointer, IP, plus
            // the specified displacement, op2. The bit specified by op1 is cleared, allowing implementation of semaphore operations.
            // The displacement is a two's complement number which is sign extended and counts the relative distance in words. The value
            // of the IP used in the target address calculation is the address of the instruction following the JBC instruction. If the
            // specified bit was clear, the instruction following the JBC instruction is executed.
            // E: Always cleared.
            // Z: Contains logical negation of the previous state of the specified bit.
            // V: Always cleared.
            // C: Always cleared.
            // N: Contains the previous state of the specified bit.

            0xAA => {
                Ok(Instruction {
                    // bitaddrQ.q, rel
                    // Jump relative and clear bit if direct bit is set
                    id: 0xAA,
                    mnemonic: "jbc",
                    encoding: EncodingType::bitaddr8_rel8_bit4_0,
                    op1: Some(OperandType::BitAddr(0)),
                    op2: Some(OperandType::DirectRelative8S),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_JMP | _RAnalOpType::R_ANAL_OP_TYPE_COND,
                    esil: "",
                })
            },

            // JMPA: Absolute Conditional Jump
            // If the condition specified by op1 is met, a branch to the absolute address specified by op2 is taken. If the condition
            // is not met, no action is taken, and the instruction following the JMPA instruction is executed normally.
            //
            // NOTE: Condition flags not affected

            0xEA => {
                Ok(Instruction {
                    // cc, caddr
                    // Jump absolute if condition is met
                    id: 0xEA,
                    mnemonic: "jmpa",
                    encoding: EncodingType::cond4_0_mem16,
                    op1: Some(OperandType::Condition),
                    op2: Some(OperandType::DirectCaddr16),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_JMP | _RAnalOpType::R_ANAL_OP_TYPE_COND,
                    esil: "",
                })
            },

            // JMPI: Indirect Conditional Jump
            // If the condition specified by op1 is met, a branch to the absolute address specified by op2 is taken. If the condition
            // is not met, no action is taken, and the instruction following the JMPI instruction is executed normally.
            //
            // NOTE: Condition flags not affected

            0x9C => {
                Ok(Instruction {
                    // cc, [Rwn]
                    // Jump indirect if condition is met
                    id: 0x9C,
                    mnemonic: "jmpi",
                    encoding: EncodingType::cond4_reg4,
                    op1: Some(OperandType::Condition),
                    op2: Some(OperandType::Indirect(0)),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_JMP | _RAnalOpType::R_ANAL_OP_TYPE_COND | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            // JMPR: Relative Conditional Jump
            // If the condition specified by op1 is met, program execution continues at the location of the instruction pointer, IP, plus
            // the specified displacement, op2. The displacement is a two's complement number which is sign extended and counts the relative
            // distance in words. The value of the IP used in the target address calculation is the address of the instruction following the
            // JMPR instruction. If the specified condition is not met, program execution continues normally with the instruction following
            // the JMPR instruction.
            //
            // NOTE: Condition flags not affected

            0x0D => {
                Ok(Instruction {
                    // cc, rel
                    // Jump relative if condition is met
                    id: 0x0D,
                    mnemonic: "jmpr",
                    encoding: EncodingType::condopcode4_d_rel8s,
                    op1: Some(OperandType::Condition),
                    op2: Some(OperandType::DirectRelative8S),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_JMP,
                    esil: "",
                })
            },

            0x1D => {
                Ok(Instruction {
                    // cc, rel
                    // Jump relative if condition is met
                    id: 0x1D,
                    mnemonic: "jmpr",
                    encoding: EncodingType::condopcode4_d_rel8s,
                    op1: Some(OperandType::Condition),
                    op2: Some(OperandType::DirectRelative8S),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_JMP | _RAnalOpType::R_ANAL_OP_TYPE_COND,
                    esil: "",
                })
            },

            0x2D => {
                Ok(Instruction {
                    // cc, rel
                    // Jump relative if condition is met
                    id: 0x2D,
                    mnemonic: "jmpr",
                    encoding: EncodingType::condopcode4_d_rel8s,
                    op1: Some(OperandType::Condition),
                    op2: Some(OperandType::DirectRelative8S),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_JMP | _RAnalOpType::R_ANAL_OP_TYPE_COND,
                    esil: "",
                })
            },

            0x3D => {
                Ok(Instruction {
                    // cc, rel
                    // Jump relative if condition is met
                    id: 0x3D,
                    mnemonic: "jmpr",
                    encoding: EncodingType::condopcode4_d_rel8s,
                    op1: Some(OperandType::Condition),
                    op2: Some(OperandType::DirectRelative8S),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_JMP | _RAnalOpType::R_ANAL_OP_TYPE_COND,
                    esil: "",
                })
            },

            0x4D => {
                Ok(Instruction {
                    // cc, rel
                    // Jump relative if condition is met
                    id: 0x4D,
                    mnemonic: "jmpr",
                    encoding: EncodingType::condopcode4_d_rel8s,
                    op1: Some(OperandType::Condition),
                    op2: Some(OperandType::DirectRelative8S),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_JMP | _RAnalOpType::R_ANAL_OP_TYPE_COND,
                    esil: "",
                })
            },

            0x5D => {
                Ok(Instruction {
                    // cc, rel
                    // Jump relative if condition is met
                    id: 0x5D,
                    mnemonic: "jmpr",
                    encoding: EncodingType::condopcode4_d_rel8s,
                    op1: Some(OperandType::Condition),
                    op2: Some(OperandType::DirectRelative8S),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_JMP | _RAnalOpType::R_ANAL_OP_TYPE_COND,
                    esil: "",
                })
            },

            0x6D => {
                Ok(Instruction {
                    // cc, rel
                    // Jump relative if condition is met
                    id: 0x6D,
                    mnemonic: "jmpr",
                    encoding: EncodingType::condopcode4_d_rel8s,
                    op1: Some(OperandType::Condition),
                    op2: Some(OperandType::DirectRelative8S),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_JMP | _RAnalOpType::R_ANAL_OP_TYPE_COND,
                    esil: "",
                })
            },

            0x7D => {
                Ok(Instruction {
                    // cc, rel
                    // Jump relative if condition is met
                    id: 0x7D,
                    mnemonic: "jmpr",
                    encoding: EncodingType::condopcode4_d_rel8s,
                    op1: Some(OperandType::Condition),
                    op2: Some(OperandType::DirectRelative8S),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_JMP | _RAnalOpType::R_ANAL_OP_TYPE_COND,
                    esil: "",
                })
            },

            0x8D => {
                Ok(Instruction {
                    // cc, rel
                    // Jump relative if condition is met
                    id: 0x8D,
                    mnemonic: "jmpr",
                    encoding: EncodingType::condopcode4_d_rel8s,
                    op1: Some(OperandType::Condition),
                    op2: Some(OperandType::DirectRelative8S),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_JMP | _RAnalOpType::R_ANAL_OP_TYPE_COND,
                    esil: "",
                })
            },

            0x9D => {
                Ok(Instruction {
                    // cc, rel
                    // Jump relative if condition is met
                    id: 0x9D,
                    mnemonic: "jmpr",
                    encoding: EncodingType::condopcode4_d_rel8s,
                    op1: Some(OperandType::Condition),
                    op2: Some(OperandType::DirectRelative8S),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_JMP | _RAnalOpType::R_ANAL_OP_TYPE_COND,
                    esil: "",
                })
            },

            0xAD => {
                Ok(Instruction {
                    // cc, rel
                    // Jump relative if condition is met
                    id: 0xAD,
                    mnemonic: "jmpr",
                    encoding: EncodingType::condopcode4_d_rel8s,
                    op1: Some(OperandType::Condition),
                    op2: Some(OperandType::DirectRelative8S),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_JMP | _RAnalOpType::R_ANAL_OP_TYPE_COND,
                    esil: "",
                })
            },

            0xBD => {
                Ok(Instruction {
                    // cc, rel
                    // Jump relative if condition is met
                    id: 0xBD,
                    mnemonic: "jmpr",
                    encoding: EncodingType::condopcode4_d_rel8s,
                    op1: Some(OperandType::Condition),
                    op2: Some(OperandType::DirectRelative8S),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_JMP | _RAnalOpType::R_ANAL_OP_TYPE_COND,
                    esil: "",
                })
            },

            0xCD => {
                Ok(Instruction {
                    // cc, rel
                    // Jump relative if condition is met
                    id: 0xCD,
                    mnemonic: "jmpr",
                    encoding: EncodingType::condopcode4_d_rel8s,
                    op1: Some(OperandType::Condition),
                    op2: Some(OperandType::DirectRelative8S),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_JMP | _RAnalOpType::R_ANAL_OP_TYPE_COND,
                    esil: "",
                })
            },

            0xDD => {
                Ok(Instruction {
                    // cc, rel
                    // Jump relative if condition is met
                    id: 0xDD,
                    mnemonic: "jmpr",
                    encoding: EncodingType::condopcode4_d_rel8s,
                    op1: Some(OperandType::Condition),
                    op2: Some(OperandType::DirectRelative8S),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_JMP | _RAnalOpType::R_ANAL_OP_TYPE_COND,
                    esil: "",
                })
            },

            0xED => {
                Ok(Instruction {
                    // cc, rel
                    // Jump relative if condition is met
                    id: 0xED,
                    mnemonic: "jmpr",
                    encoding: EncodingType::condopcode4_d_rel8s,
                    op1: Some(OperandType::Condition),
                    op2: Some(OperandType::DirectRelative8S),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_JMP | _RAnalOpType::R_ANAL_OP_TYPE_COND,
                    esil: "",
                })
            },

            0xFD => {
                Ok(Instruction {
                    // cc, rel
                    // Jump relative if condition is met
                    id: 0xFD,
                    mnemonic: "jmpr",
                    encoding: EncodingType::condopcode4_d_rel8s,
                    op1: Some(OperandType::Condition),
                    op2: Some(OperandType::DirectRelative8S),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_JMP | _RAnalOpType::R_ANAL_OP_TYPE_COND,
                    esil: "",
                })
            },

            // JMPS: Absolute Inter-Segment Jump
            // Branches unconditionally to the absolute address specified by op2 within the segment specified by op1.
            //
            // NOTE: Condition flags not affected

            0xFA => {
                Ok(Instruction {
                    // seg, caddr
                    // Jump absolute to a code segment
                    id: 0xFA,
                    mnemonic: "jmps",
                    encoding: EncodingType::seg8_mem16,
                    op1: Some(OperandType::DirectSegment8),
                    op2: Some(OperandType::DirectCaddr16),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_JMP,
                    esil: "",
                })
            },

            // JNB: Relative Jump if Bit Clear
            // If the bit specified by op1 is clear, program execution continues at the location of the instruction pointer,
            // IP, plus the specified displacement, op2. The displacement is a two's complement number which is sign extended
            // and counts the relative distance in words. The value of the IP used in the target address calculation is the
            // address of the instruction following the JNB instruction. If the specified bit is set, the instruction following
            // the JNB instruction is executed.
            //
            // NOTE: Condition flags not affected

            0x9A => {
                Ok(Instruction {
                    // bitaddrQ.q, rel
                    // Jump relative if direct bit is not set
                    id: 0x9A,
                    mnemonic: "jnb",
                    encoding: EncodingType::bitaddr8_rel8_bit4_0,
                    op1: Some(OperandType::BitAddr(0)),
                    op2: Some(OperandType::DirectRelative8S),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_JMP | _RAnalOpType::R_ANAL_OP_TYPE_COND,
                    esil: "",
                })
            },

            // JNBS: Relative Jump if Bit Clear and Set Bit
            // If the bit specified by op1 is clear, program execution continues at the location of the instruction
            // pointer, IP, plus the specified displacement, op2. The bit specified by op1 is set, allowing implementation
            // of semaphore operations. The displacement is a two's complement number which is sign extended and counts the
            // relative distance in words. The value of the IP used in the target address calculation is the address of the
            // instruction following the JNBS instruction. If the specified bit was set, the instruction following the JNBS
            // instruction is executed.
            // E: Always cleared.
            // Z: Contains logical negation of the previous state of the specified bit.
            // V: Always cleared.
            // C: Always cleared.
            // N: Contains the previous state of the specified bit.

            0xBA => {
                Ok(Instruction {
                    // bitaddrQ.q, rel
                    // Jump relative and set bit if direct bit is not set
                    id: 0xBA,
                    mnemonic: "jnbs",
                    encoding: EncodingType::bitaddr8_rel8_bit4_0,
                    op1: Some(OperandType::BitAddr(0)),
                    op2: Some(OperandType::DirectRelative8S),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_JMP | _RAnalOpType::R_ANAL_OP_TYPE_COND,
                    esil: "",
                })
            },

            // MOV: Move Data
            // Moves the contents of the source operand specified by op2 to the location specified by the destination operand op1.
            // The contents of the moved data is examined, and the condition codes are updated accordingly.
            // E: Set if the value of op2 represents the lowest possible negative number. Cleared otherwise. Used to signal the end of a table.
            // Z: Set if the value of the source operand op2 equals zero. Cleared otherwise.
            // V: Not affected.
            // C: Not affected.
            // N: Set if the most significant bit of the source operand op2 is set. Cleared otherwise.

            0xF0 => {
                Ok(Instruction {
                    // Rwn, Rwm
                    // Move direct word GPR to direct GPR
                    id: 0xF0,
                    mnemonic: "mov",
                    encoding: EncodingType::reg4_reg4,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: Some(OperandType::WordRegister(1)),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "{op2},NUM,{op1},=",
                })
            },

            0xE0 => {
                Ok(Instruction {
                    // Rwn, #data4
                    // Move immediate word data to direct GPR
                    id: 0xE0,
                    mnemonic: "mov",
                    encoding: EncodingType::reg4_data4,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: Some(OperandType::ImmediateData4),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "{op2},{op1},=",
                })
            },

            0xE6 => {
                Ok(Instruction {
                    // reg, #data16
                    // Move immediate word data to direct register
                    id: 0xE6,
                    mnemonic: "mov",
                    encoding: EncodingType::reg8_data16,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: Some(OperandType::ImmediateData16),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "{op2},{op1},=",
                })
            },

            0xA8 => {
                Ok(Instruction {
                    // Rwn, [Rwm]
                    // Move indirect word memory to direct GPR
                    id: 0xA8,
                    mnemonic: "mov",
                    encoding: EncodingType::reg4_reg4,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: Some(OperandType::Indirect(1)),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            0x98 => {
                Ok(Instruction {
                    // Rwn, [Rwm+]
                    // Move indirect word memory to direct GPR and post-increment source pointer by 2
                    id: 0x98,
                    mnemonic: "mov",
                    encoding: EncodingType::reg4_reg4,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: Some(OperandType::IndirectPostIncrement(1)),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            0xB8 => {
                Ok(Instruction {
                    // [Rwm], Rwn
                    // Move direct word GPR to indirect memory
                    id: 0xB8,
                    mnemonic: "mov",
                    encoding: EncodingType::reg4_reg4,
                    op1: Some(OperandType::Indirect(1)),
                    op2: Some(OperandType::WordRegister(0)),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            0x88 => {
                Ok(Instruction {
                    // [-Rwm], Rwn
                    // Pre-decrement destination pointer by 2 and move direct word GPR to indirect memory
                    id: 0x88,
                    mnemonic: "mov",
                    encoding: EncodingType::reg4_reg4,
                    op1: Some(OperandType::IndirectPreDecrement(1)),
                    op2: Some(OperandType::WordRegister(0)),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            0xC8 => {
                Ok(Instruction {
                    // [Rwn], [Rwm]
                    // Move indirect word memory to indirect memory
                    id: 0xC8,
                    mnemonic: "mov",
                    encoding: EncodingType::reg4_reg4,
                    op1: Some(OperandType::Indirect(0)),
                    op2: Some(OperandType::Indirect(1)),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            0xD8 => {
                Ok(Instruction {
                    // [Rwn+], [Rwm]
                    // Move indirect word memory to indirect memory and post-increment destination pointer by 2
                    id: 0xD8,
                    mnemonic: "mov",
                    encoding: EncodingType::reg4_reg4,
                    op1: Some(OperandType::IndirectPostIncrement(0)),
                    op2: Some(OperandType::Indirect(1)),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            0xE8 => {
                Ok(Instruction {
                    // [Rwn], [Rwm+]
                    // Move indirect word memory to indirect memory and post-increment source pointer by 2
                    id: 0xE8,
                    mnemonic: "mov",
                    encoding: EncodingType::reg4_reg4,
                    op1: Some(OperandType::Indirect(0)),
                    op2: Some(OperandType::IndirectPostIncrement(1)),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            0xD4 => {
                Ok(Instruction {
                    // Rwn, [Rwm+#data16]
                    // Move indirect word memory by base plus constant to direct word GPR
                    id: 0xD4,
                    mnemonic: "mov",
                    encoding: EncodingType::reg4_reg4_data16,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: Some(OperandType::IndirectAndImmediate(1)),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "{op2},NUM,{immed},+,[],{op1}",
                })
            },

            0xC4 => {
                Ok(Instruction {
                    // [Rwm+#data16], Rwn
                    // Move direct word GPR to indirect memory by base plus constant
                    id: 0xC4,
                    mnemonic: "mov",
                    encoding: EncodingType::reg4_reg4_data16,
                    op1: Some(OperandType::IndirectAndImmediate(1)),
                    op2: Some(OperandType::WordRegister(0)),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "{op2},{op1},NUM,{immed},+,=[]",
                })
            },

            0x84 => {
                Ok(Instruction {
                    // [Rwn], mem
                    // Move direct word memory to indirect memory
                    id: 0x84,
                    mnemonic: "mov",
                    encoding: EncodingType::_0_reg4_mem16,
                    op1: Some(OperandType::Indirect(0)),
                    op2: Some(OperandType::DirectMemory16),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            0x94 => {
                Ok(Instruction {
                    // mem, [Rwn]
                    // Move indirect word memory to direct memory
                    id: 0x94,
                    mnemonic: "mov",
                    encoding: EncodingType::_0_reg4_mem16,
                    op1: Some(OperandType::DirectMemory16),
                    op2: Some(OperandType::Indirect(0)),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            0xF2 => {
                Ok(Instruction {
                    // reg, mem
                    // Move direct word memory to direct register
                    id: 0xF2,
                    mnemonic: "mov",
                    encoding: EncodingType::reg8_mem16,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: Some(OperandType::DirectMemory16),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            0xF6 => {
                Ok(Instruction {
                    // mem, reg
                    // Move direct word register to direct memory
                    id: 0xF6,
                    mnemonic: "mov",
                    encoding: EncodingType::reg8_mem16,
                    op1: Some(OperandType::DirectMemory16),
                    op2: Some(OperandType::WordRegister(0)),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            // MOVB: Move Data
            // Moves the contents of the source operand specified by op2 to the location specified by the destination operand
            // op1. The contents of the moved data is examined, and the condition codes are updated accordingly.
            // E: Set if the value of op2 represents the lowest possible negative number. Cleared otherwise. Used to signal the end of a table.
            // Z: Set if the value of the source operand op2 equals zero. Cleared otherwise.
            // V: Not affected.
            // C: Not affected.
            // N: Set if the most significant bit of the source operand op2 is set. Cleared otherwise.

            0xF1 => {
                Ok(Instruction {
                    // Rbn, Rbm
                    // Move direct byte GPR to direct GPR
                    id: 0xF1,
                    mnemonic: "movb",
                    encoding: EncodingType::reg4_reg4,
                    op1: Some(OperandType::ByteRegister(0)),
                    op2: Some(OperandType::ByteRegister(1)),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            0xE1 => {
                Ok(Instruction {
                    // Rbn, #data4
                    // Move immediate byte data to direct GPR
                    id: 0xE1,
                    mnemonic: "movb",
                    encoding: EncodingType::reg4_data4,
                    op1: Some(OperandType::ByteRegister(0)),
                    op2: Some(OperandType::ImmediateData4),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            0xE7 => {
                Ok(Instruction {
                    // reg, #data8
                    // Move immediate byte data to direct register
                    id: 0xE7,
                    mnemonic: "movb",
                    encoding: EncodingType::reg8_data8_nop8,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: Some(OperandType::ImmediateData8),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "{op2},{op1},=",
                })
            },

            0xA9 => {
                Ok(Instruction {
                    // Rbn, [Rwm]
                    // Move indirect byte memory to direct GPR
                    id: 0xA9,
                    mnemonic: "movb",
                    encoding: EncodingType::reg4_reg4,
                    op1: Some(OperandType::ByteRegister(0)),
                    op2: Some(OperandType::Indirect(1)),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            0x99 => {
                Ok(Instruction {
                    // Rbn, [Rwm+]
                    // Move indirect byte memory to direct GPR and post-increment source pointer by 1
                    id: 0x99,
                    mnemonic: "movb",
                    encoding: EncodingType::reg4_reg4,
                    op1: Some(OperandType::ByteRegister(0)),
                    op2: Some(OperandType::IndirectPostIncrement(1)),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            0xB9 => {
                Ok(Instruction {
                    // [Rwm], Rbn
                    // Move direct byte GPR to indirect memory
                    id: 0xB9,
                    mnemonic: "movb",
                    encoding: EncodingType::reg4_reg4,
                    op1: Some(OperandType::Indirect(1)),
                    op2: Some(OperandType::ByteRegister(0)),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            0x89 => {
                Ok(Instruction {
                    // [-Rwm], Rbn
                    // Pre-decrement destination pointer by 1 and move direct byte GPR to indirect memory
                    id: 0x89,
                    mnemonic: "movb",
                    encoding: EncodingType::reg4_reg4,
                    op1: Some(OperandType::IndirectPreDecrement(1)),
                    op2: Some(OperandType::ByteRegister(0)),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            0xC9 => {
                Ok(Instruction {
                    // [Rwn], [Rwm]
                    // Move indirect byte memory to indirect memory
                    id: 0xC9,
                    mnemonic: "movb",
                    encoding: EncodingType::reg4_reg4,
                    op1: Some(OperandType::Indirect(0)),
                    op2: Some(OperandType::Indirect(1)),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            0xD9 => {
                Ok(Instruction {
                    // [Rwn+], [Rwm]
                    // Move indirect byte memory to indirect memory and post-increment destination pointer by 1
                    id: 0xD9,
                    mnemonic: "movb",
                    encoding: EncodingType::reg4_reg4,
                    op1: Some(OperandType::IndirectPostIncrement(0)),
                    op2: Some(OperandType::Indirect(1)),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            0xE9 => {
                Ok(Instruction {
                    // [Rwn], [Rwm+]
                    // Move indirect byte memory to indirect memory and post-increment source pointer by 1
                    id: 0xE9,
                    mnemonic: "movb",
                    encoding: EncodingType::reg4_reg4,
                    op1: Some(OperandType::Indirect(0)),
                    op2: Some(OperandType::IndirectPostIncrement(1)),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            0xF4 => {
                Ok(Instruction {
                    // Rbn, [Rwm+#data16]
                    // Move indirect byte memory by base plus constant to direct byte GPR
                    id: 0xF4,
                    mnemonic: "movb",
                    encoding: EncodingType::reg4_reg4_data16,
                    op1: Some(OperandType::ByteRegister(0)),
                    op2: Some(OperandType::IndirectAndImmediate(1)),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            0xE4 => {
                Ok(Instruction {
                    // [Rwm+#data16], Rbn
                    // Move direct byte GPR to indirect memory by base plus constant
                    id: 0xE4,
                    mnemonic: "movb",
                    encoding: EncodingType::reg4_reg4_data16,
                    op1: Some(OperandType::IndirectAndImmediate(1)),
                    op2: Some(OperandType::ByteRegister(0)),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "{op2},{op1},NUM,{immed},+,=[]",
                })
            },

            0xA4 => {
                Ok(Instruction {
                    // [Rwn], mem
                    // Move direct byte memory to indirect memory
                    id: 0xA4,
                    mnemonic: "movb",
                    encoding: EncodingType::_0_reg4_mem16,
                    op1: Some(OperandType::Indirect(0)),
                    op2: Some(OperandType::DirectMemory16),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            0xB4 => {
                Ok(Instruction {
                    // mem, [Rwn]
                    // Move indirect byte memory to direct memory
                    id: 0xB4,
                    mnemonic: "movb",
                    encoding: EncodingType::_0_reg4_mem16,
                    op1: Some(OperandType::DirectMemory16),
                    op2: Some(OperandType::Indirect(0)),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            0xF3 => {
                Ok(Instruction {
                    // reg, mem
                    // Move direct byte memory to direct register
                    id: 0xF3,
                    mnemonic: "movb",
                    encoding: EncodingType::reg8_mem16,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: Some(OperandType::DirectMemory16),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            0xF7 => {
                Ok(Instruction {
                    // mem, reg
                    // Move direct byte register to direct memory
                    id: 0xF7,
                    mnemonic: "movb",
                    encoding: EncodingType::reg8_mem16,
                    op1: Some(OperandType::DirectMemory16),
                    op2: Some(OperandType::WordRegister(0)),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            // MOVBS: Move Byte Sign Extend
            // Moves and sign extends the contents of the source byte specified by op2 to the word location specified
            // by the destination operand op1. The contents of the moved data is examined, and the condition codes are
            // updated accordingly.
            // E: Always cleared.
            // Z: Set if the value of the source operand op2 equals zero. Cleared otherwise.
            // V: Not affected.
            // C: Not affected.
            // N: Set if the most significant bit of the source operand op2 is set. Cleared otherwise.

            0xD0 => {
                Ok(Instruction {
                    // Rwn, Rbm  (enc = mn)
                    // Move direct byte GPR with sign extension to direct word GPR
                    id: 0xD0,
                    mnemonic: "movbs",
                    encoding: EncodingType::reg4_reg4,
                    op1: Some(OperandType::WordRegister(1)),
                    op2: Some(OperandType::ByteRegister(0)),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
               })
            },

            0xD2 => {
                Ok(Instruction {
                    // reg, mem
                    // Move direct byte memory with sign extension to direct word register
                    id: 0xD2,
                    mnemonic: "movbs",
                    encoding: EncodingType::reg8_mem16,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: Some(OperandType::DirectMemory16),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            0xD5 => {
                Ok(Instruction {
                    // mem, reg
                    // Move direct byte register with sign extension to direct word memory
                    id: 0xD5,
                    mnemonic: "movbs",
                    encoding: EncodingType::reg8_mem16,
                    op1: Some(OperandType::DirectMemory16),
                    op2: Some(OperandType::WordRegister(0)),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            // MOVBZ: Move Byte Zero Extend
            // Moves and zero extends the contents of the source byte specified by op2 to the word location specified
            // by the destination operand op1. The contents of the moved data is examined, and the condition codes are
            // updated accordingly.
            // E: Always cleared.
            // Z: Set if the value of the source operand op2 equals zero. Cleared otherwise.
            // V: Not affected.
            // C: Not affected.
            // N: Always cleared.

            0xC0 => {
                Ok(Instruction {
                    // Rwn, Rbm (enc = mn)
                    // Move direct byte GPR with zero extension to direct word GPR
                    id: 0xC0,
                    mnemonic: "movbz",
                    encoding: EncodingType::reg4_reg4,
                    op1: Some(OperandType::WordRegister(1)),
                    op2: Some(OperandType::ByteRegister(0)),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            0xC2 => {
                Ok(Instruction {
                    // reg, mem
                    // Move direct byte memory with zero extension to direct word register
                    id: 0xC2,
                    mnemonic: "movbz",
                    encoding: EncodingType::reg8_mem16,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: Some(OperandType::DirectMemory16),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            0xC5 => {
                Ok(Instruction {
                    // mem, reg
                    // Move direct byte register with zero extension to direct word memory
                    id: 0xC5,
                    mnemonic: "movbz",
                    encoding: EncodingType::reg8_mem16,
                    op1: Some(OperandType::DirectMemory16),
                    op2: Some(OperandType::WordRegister(0)),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            // MUL: Signed Multiplication
            // Performs a 16-bit by 16-bit signed multiplication using the two words specified by operands op1 and op2
            // respectively. The signed 32-bit result is placed in the MD register.
            //
            // NOTE: MUL is interruptable.
            // E: Always cleared.
            // Z: Set if the result equals zero. Cleared otherwise.
            // V: This bit is set if the result cannot be represented in a word data type. Cleared otherwise.
            // C: Always cleared.
            // N: Set if the most significant bit of the result is set. Cleared otherwise.

            0x0B => {
                Ok(Instruction {
                    // Rwn, Rwm
                    // Signed multiply direct GPR by direct GPR (16-bit × 16-bit)
                    id: 0x0B,
                    mnemonic: "mul",
                    encoding: EncodingType::reg4_reg4,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: Some(OperandType::WordRegister(1)),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MUL | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            // MULU: Unsigned Multiplication
            // Performs a 16-bit by 16-bit unsigned multiplication using the two words specified by operands op1 and
            // op2 respectively. The unsigned 32-bit result is placed in the MD register.
            //
            // NOTE: MULU is interruptable.
            // E: Always cleared.
            // Z: Set if the result equals zero. Cleared otherwise.
            // V: This bit is set if the result cannot be represented in a word data type. Cleared otherwise.
            // C: Always cleared.
            // N: Set if the most significant bit of the result is set. Cleared otherwise.

            0x1B => {
                Ok(Instruction {
                    // Rwn, Rwm
                    // Unsigned multiply direct GPR by direct GPR (16-bit × 16-bit)
                    id: 0x1B,
                    mnemonic: "mulu",
                    encoding: EncodingType::reg4_reg4,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: Some(OperandType::WordRegister(1)),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MUL | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            // NEG: Integer Two's Complement
            // Performs a binary 2's complement of the source operand specified by op1. The result is then stored in op1.
            // E: Set if the value of op1 represents the lowest possible negative number. Cleared otherwise. Used to signal the end of a table.
            // Z: Set if result equals zero. Cleared otherwise.
            // V: Set if an arithmetic underflow occurred, i.e. the result cannot be represented in the specified data type. Cleared otherwise.
            // C: Set if a borrow is generated. Cleared otherwise.
            // N: Set if the most significant bit of the result is set. Cleared otherwise.

            0x81 => {
                Ok(Instruction {
                    // Rwn
                    // Negate direct word GPR
                    id: 0x81,
                    mnemonic: "neg",
                    encoding: EncodingType::reg4_0,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: None,
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CPL | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            // NEGB: Integer Two's Complement
            // Performs a binary 2's complement of the source operand specified by op1. The result is then stored in op1.
            // E: Set if the value of op1 represents the lowest possible negative number. Cleared otherwise. Used to signal the end of a table.
            // Z: Set if result equals zero. Cleared otherwise.
            // V: Set if an arithmetic underflow occurred, i.e. the result cannot be represented in the specified data type. Cleared otherwise.
            // C: Set if a borrow is generated. Cleared otherwise.
            // N: Set if the most significant bit of the result is set. Cleared otherwise.

            0xA1 => {
                Ok(Instruction {
                    // Rbn
                    // Negate direct byte GPR
                    id: 0xA1,
                    mnemonic: "negb",
                    encoding: EncodingType::reg4_0,
                    op1: Some(OperandType::ByteRegister(0)),
                    op2: None,
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CPL | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            // NOP: No Operation
            // This instruction causes a null operation to be performed. A null operation causes no change in the status
            // of the flags.

            0xCC => {
                Ok(Instruction {
                    // ---
                    // Null operation
                    id: 0xCC,
                    mnemonic: "nop",
                    encoding: EncodingType::NO_ARGS2,
                    op1: None,
                    op2: None,
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_NOP,
                    esil: "",
                })
            },

            // OR: Logical OR
            // Performs a bitwise logical OR of the source operand specified by op2 and the destination operand specified by
            // op1. The result is then stored in op1.
            // E: Set if the value of op2 represents the lowest possible negative number. Cleared otherwise. Used to signal the end of a table.
            // Z: Set if result equals zero. Cleared otherwise.
            // V: Always cleared.
            // C: Always cleared.
            // N: Set if the most significant bit of the result is set. Cleared otherwise.

            0x70 => {
                Ok(Instruction {
                    // Rwn, Rwm
                    // Bitwise OR direct word GPR with direct GPR
                    id: 0x70,
                    mnemonic: "or",
                    encoding: EncodingType::reg4_reg4,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: Some(OperandType::WordRegister(1)),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_OR | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "{op2},NUM,{op1},|",
                })
            },

            0x78 => {
                Ok(Instruction {
                    // Rwn, [Rwi]
                    // Bitwise OR indirect word memory with direct GPR
                    // Rwn, [Rwi+]
                    // Bitwise OR indirect word memory with direct GPR and post-increment source pointer by 2
                    // Rwn, #data3
                    // Bitwise OR immediate word data with direct GPR
                    id: 0x78,
                    mnemonic: "or",
                    encoding: EncodingType::reg4_or_data3,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: Some(OperandType::ImmediateData3),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_OR,
                    esil: "",
                })
            },

            0x76 => {
                Ok(Instruction {
                    // reg, #data16
                    // Bitwise OR immediate word data with direct register
                    id: 0x76,
                    mnemonic: "or",
                    encoding: EncodingType::reg8_data16,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: Some(OperandType::ImmediateData16),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_OR | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            0x72 => {
                Ok(Instruction {
                    // reg, mem
                    // Bitwise OR direct word memory with direct register
                    id: 0x72,
                    mnemonic: "or",
                    encoding: EncodingType::reg8_mem16,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: Some(OperandType::DirectMemory16),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_OR | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            0x74 => {
                Ok(Instruction {
                    // mem, reg
                    // Bitwise OR direct word register with direct memory
                    id: 0x74,
                    mnemonic: "or",
                    encoding: EncodingType::reg8_mem16,
                    op1: Some(OperandType::DirectMemory16),
                    op2: Some(OperandType::WordRegister(0)),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_OR | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            // ORB: Logical OR
            // Performs a bitwise logical OR of the source operand specified by op2 and the destination operand specified by
            // op1. The result is then stored in op1.
            // E: Set if the value of op2 represents the lowest possible negative number. Cleared otherwise. Used to signal the end of a table.
            // Z: Set if result equals zero. Cleared otherwise.
            // V: Always cleared.
            // C: Always cleared.
            // N: Set if the most significant bit of the result is set. Cleared otherwise.

            0x71 => {
                Ok(Instruction {
                    // Rbn, Rbm
                    // Bitwise OR direct byte GPR with direct GPR
                    id: 0x71,
                    mnemonic: "orb",
                    encoding: EncodingType::reg4_reg4,
                    op1: Some(OperandType::ByteRegister(0)),
                    op2: Some(OperandType::ByteRegister(1)),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_OR | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            0x79 => {
                Ok(Instruction {
                    // Rbn, [Rwi]
                    // Bitwise OR indirect byte memory with direct GPR
                    // Rbn, [Rwi+]
                    // Bitwise OR indirect byte memory with direct GPR and post-increment source pointer by 1
                    // Rbn, #data3
                    // Bitwise OR immediate byte data with direct GPR
                    id: 0x79,
                    mnemonic: "orb",
                    encoding: EncodingType::reg4_or_data3,
                    op1: Some(OperandType::ByteRegister(0)),
                    op2: Some(OperandType::ImmediateData3),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_OR,
                    esil: "",
                })
            },

            0x77 => {
                Ok(Instruction {
                    // reg, #data8
                    // Bitwise OR immediate byte data with direct register
                    id: 0x77,
                    mnemonic: "orb",
                    encoding: EncodingType::reg8_data8_nop8,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: Some(OperandType::ImmediateData8),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_OR | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            0x73 => {
                Ok(Instruction {
                    // reg, mem
                    // Bitwise OR direct byte memory with direct register
                    id: 0x73,
                    mnemonic: "orb",
                    encoding: EncodingType::reg8_mem16,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: Some(OperandType::DirectMemory16),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_OR | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            0x75 => {
                Ok(Instruction {
                    // mem, reg
                    // Bitwise OR direct byte register with direct memory
                    id: 0x75,
                    mnemonic: "orb",
                    encoding: EncodingType::reg8_mem16,
                    op1: Some(OperandType::DirectMemory16),
                    op2: Some(OperandType::WordRegister(0)),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_OR | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            // PCALL: Push Word and Call Subroutine Absolute
            // Pushes the word specified by operand op1 and the value of the instruction pointer, IP, onto the system
            // stack, and branches to the absolute memory location specified by the second operand op2. Because IP always
            // points to the instruction following the branch instruction, the value stored on the system stack represents
            // the return address of the calling routine.
            // E: Set if the value of the pushed operand op1 represents the lowest possible negative number. Cleared otherwise. Used to signal the end of a table.
            // Z: Set if the value of the pushed operand op1 equals zero. Cleared otherwise.
            // V: Not affected.
            // C: Not affected.
            // N: Set if the most significant bit of the pushed operand op1 is set. Cleared otherwise.

            0xE2 => {
                Ok(Instruction {
                    // reg, caddr
                    // Push direct word register onto system stack and call absolute subroutine
                    id: 0xE2,
                    mnemonic: "pcall",
                    encoding: EncodingType::reg8_mem16,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: Some(OperandType::DirectCaddr16),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CALL | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            // POP: Pop Word from System Stack
            // Pops one word from the system stack specified by the Stack Pointer into the operand specified by op1. The Stack
            // Pointer is then incremented by two.
            // E: Set if the value of the popped word represents the lowest possible negative number. Cleared otherwise. Used to signal the end of a table.
            // Z: Set if the value of the popped word equals zero. Cleared otherwise.
            // V: Not affected.
            // C: Not affected.
            // N: Set if the most significant bit of the popped word is set. Cleared otherwise.

            0xFC => {
                Ok(Instruction {
                    // reg
                    // Pop direct word register from system stack
                    id: 0xFC,
                    mnemonic: "pop",
                    encoding: EncodingType::reg8,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: None,
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_POP | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            // PRIOR: Prioritize Register
            // This instruction stores a count value in the word operand specified by op1 indicating the number of single bit
            // shifts required to normalize the operand op2 so that its MSB is equal to one. If the source operand op2 equals
            // zero, a zero is written to operand op1 and the zero flag is set. Otherwise the zero flag is cleared.
            // E: Always cleared.
            // Z: Set if the source operand op2 equals zero. Cleared otherwise.
            // V: Always cleared.
            // C: Always cleared.
            // N: Always cleared.

            0x2B => {
                Ok(Instruction {
                    // Rwn, Rwm
                    // Determine number of shift cycles to normalize direct word GPR and store result in direct word GPR
                    id: 0x2B,
                    mnemonic: "prior",
                    encoding: EncodingType::reg4_reg4,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: Some(OperandType::WordRegister(1)),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_NULL | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            // PUSH: Push Word on System Stack
            // Moves the word specified by operand op1 to the location in the internal system stack specified by the Stack Pointer,
            // after the Stack Pointer has been decremented by two.
            // E: Set if the value of the pushed word represents the lowest possible negative number. Cleared otherwise. Used to signal the end of a table.
            // Z: Set if the value of the pushed word equals zero. Cleared otherwise.
            // V: Not affected.
            // C: Not affected.
            // N: Set if the most significant bit of the pushed word is set. Cleared otherwise.

            0xEC => {
                Ok(Instruction {
                    // reg
                    // Push direct word register onto system stack
                    id: 0xEC,
                    mnemonic: "push",
                    encoding: EncodingType::reg8,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: None,
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_PUSH | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            // PWRDN: Enter Power Down Mode
            // This instruction causes the part to enter the power down mode. In this mode, all peripherals and the CPU are
            // powered down until the part is externally reset. To further control the action of this instruction, the PWRDN
            // instruction is only enabled when the non-maskable interrupt pin (NMI) is in the low state. Otherwise, this
            // instruction has no effect.
            //
            // NOTE: To insure that this instruction is not accidentally executed, it is implemented as a protected instruction.
            // NOTE: Condition flags not affected

            0x97 => {
                Ok(Instruction {
                    // ---
                    // Enter Power Down Mode (supposes NMI-pin being low)
                    id: 0x97,
                    mnemonic: "pwrdn",
                    encoding: EncodingType::NO_ARGS4,
                    op1: None,
                    op2: None,
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_NULL,
                    esil: "",
                })
            },

            // RET: Return from Subroutine
            // Returns from a subroutine. The IP is popped from the system stack. Execution resumes at the instruction following
            // the CALL instruction in the calling routine.
            //
            // NOTE: Condition flags not affected

            0xCB => {
                Ok(Instruction {
                    // ---
                    // Return from intra-segment subroutine
                    id: 0xCB,
                    mnemonic: "ret",
                    encoding: EncodingType::NO_ARGS2,
                    op1: None,
                    op2: None,
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_RET,
                    esil: "",
                })
            },

            // RETI: Return from Interrupt Routine
            // Returns from an interrupt routine. The PSW, IP, and CSP are popped off the system stack. Execution resumes at the
            // instruction which had been interrupted. The previous system state is restored after the PSW has been popped. The
            // CSP is only popped if segmentation is enabled. This is indicated by the SGTDIS bit in the SYSCON register.
            // E: Restored from the PSW popped from stack.
            // Z: Restored from the PSW popped from stack.
            // V: Restored from the PSW popped from stack.
            // C: Restored from the PSW popped from stack.
            // N: Restored from the PSW popped from stack.

            0xFB => {
                Ok(Instruction {
                    // ---
                    // Return from interrupt service subroutine
                    id: 0xFB,
                    mnemonic: "reti",
                    encoding: EncodingType::NO_ARGS2,
                    op1: None,
                    op2: None,
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_RET,
                    esil: "",
                })
            },

            // RETP: Return from Subroutine and Pop Word
            // Returns from a subroutine. The IP is first popped from the system stack and then the next word is popped from the
            // system stack into the operand specified by op1. Execution resumes at the instruction following the CALL instruction
            // in the calling routine.
            // E: Set if the value of the word popped into operand op1 represents the lowest possible negative number. Cleared otherwise. Used to signal the end of a table.
            // Z: Set if the value of the word popped into operand op1 equals zero. Cleared otherwise.
            // V: Not affected.
            // C: Not affected.
            // N: Set if the most significant bit of the word popped into operand op1 is set. Cleared otherwise.

            0xEB => {
                Ok(Instruction {
                    // reg
                    // Return from intra-segment subroutine and pop direct word register from system stack
                    id: 0xEB,
                    mnemonic: "retp",
                    encoding: EncodingType::reg8,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: None,
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_RET | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            // RETS: Return from Inter-Segment Subroutine
            // Returns from an inter-segment subroutine. The IP and CSP are popped from the system stack. Execution resumes at the
            // instruction following the CALLS instruction in the calling routine.
            //
            // NOTE: Condition flags not affected

            0xDB => {
                Ok(Instruction {
                    // ---
                    // Return from inter-segment subroutine
                    id: 0xDB,
                    mnemonic: "rets",
                    encoding: EncodingType::NO_ARGS2,
                    op1: None,
                    op2: None,
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_RET,
                    esil: "",
                })
            },

            // ROL: Rotate Left
            // Rotates the destination word operand op1 left by as many times as specified by the source operand op2. Bit 15 is rotated
            // into Bit 0 and into the Carry. Only shift values between 0 and 15 are allowed. When using a GPR as the count control,
            // only the least significant 4 bits are used.
            // E: Always cleared.
            // Z: Set if result equals zero. Cleared otherwise.
            // V: Always cleared.
            // C: The carry flag is set according to the last MSB shifted out of op1. Cleared for a rotate count of zero.
            // N: Set if the most significant bit of the result is set. Cleared otherwise.

            0x0C => {
                Ok(Instruction {
                    // Rwn, Rwm
                    // Rotate left direct word GPR; number of shift cycles specified by direct GPR
                    id: 0x0C,
                    mnemonic: "rol",
                    encoding: EncodingType::reg4_reg4,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: Some(OperandType::WordRegister(1)),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_ROL | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "{op2},NUM,{op1},<<<",
                })
            },

            0x1C => {
                Ok(Instruction {
                    // Rwn, #data4
                    // Rotate left direct word GPR; number of shift cycles specified by immediate data
                    id: 0x1C,
                    mnemonic: "rol",
                    encoding: EncodingType::reg4_data4,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: Some(OperandType::ImmediateData4),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_ROL | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "{op2},{op1},<<<",
                })
            },

            // ROR: Rotate Right
            // Rotates the destination word operand op1 right by as many times as specified by the source operand op2.
            // Bit 0 is rotated into Bit 15 and into the Carry. Only shift values between 0 and 15 are allowed. When
            // using a GPR as the count control, only the least significant 4 bits are used.
            // E: Always cleared.
            // Z: Set if result equals zero. Cleared otherwise.
            // V: Set if in any cycle of the rotate operation a '1' is shifted out of the carry flag. Cleared for a rotate count of zero.
            // C: The carry flag is set according to the last LSB shifted out of op1. Cleared for a rotate count of zero.
            // N: Set if the most significant bit of the result is set. Cleared otherwise.

            0x2C => {
                Ok(Instruction {
                    // Rwn, Rwm
                    // Rotate right direct word GPR; number of shift cycles specified by direct GPR
                    id: 0x2C,
                    mnemonic: "ror",
                    encoding: EncodingType::reg4_reg4,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: Some(OperandType::WordRegister(1)),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_ROR | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "{op2},NUM,{op1},>>>",
                })
            },

            0x3C => {
                Ok(Instruction {
                    // Rwn, #data4
                    // Rotate right direct word GPR; number of shift cycles specified by immediate data
                    id: 0x3C,
                    mnemonic: "ror",
                    encoding: EncodingType::reg4_data4,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: Some(OperandType::ImmediateData4),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_ROR | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            // SCXT: Switch Context
            // Used to switch contexts for any register. Switching context is a push and load operation. The contents of
            // the register specified by the first operand, op1, are pushed onto the stack. That register is then loaded
            // with the value specified by the second operand, op2.
            //
            // NOTE: Condition flags not affected

            0xC6 => {
                Ok(Instruction {
                    // reg, #data16
                    // Push direct word register onto system stack and update register with immediate data
                    id: 0xC6,
                    mnemonic: "scxt",
                    encoding: EncodingType::reg8_data16,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: Some(OperandType::ImmediateData16),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_NULL | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            0xD6 => {
                Ok(Instruction {
                    // reg, mem
                    // Push direct word register onto system stack and update register with direct memory
                    id: 0xD6,
                    mnemonic: "scxt",
                    encoding: EncodingType::reg8_mem16,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: Some(OperandType::DirectMemory16),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_NULL | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            // SHL: Shift Left
            // Shifts the destination word operand op1 left by as many times as specified by the source operand op2. The
            // least significant bits of the result are filled with zeros accordingly. The MSB is shifted into the Carry.
            // Only shift values between 0 and 15 are allowed. When using a GPR as the count control, only the least significant
            // 4 bits are used.
            // E: Always cleared.
            // Z: Set if result equals zero. Cleared otherwise.
            // V: Always cleared.
            // C: The carry flag is set according to the last MSB shifted out of op1. Cleared for a shift count of zero.
            // N: Set if the most significant bit of the result is set. Cleared otherwise.

            0x4C => {
                Ok(Instruction {
                    // Rwn, Rwm
                    // Shift left direct word GPR; number of shift cycles specified by direct GPR
                    id: 0x4C,
                    mnemonic: "shl",
                    encoding: EncodingType::reg4_reg4,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: Some(OperandType::WordRegister(1)),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_SHL | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            0x5C => {
                Ok(Instruction {
                    // Rwn, #data4
                    // Shift left direct word GPR; number of shift cycles specified by immediate data
                    id: 0x5C,
                    mnemonic: "shl",
                    encoding: EncodingType::reg4_data4,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: Some(OperandType::ImmediateData4),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_SHL | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            // SHR: Shift Right
            // Shifts the destination word operand op1 right by as many times as specified by the source operand op2. The most significant
            // bits of the result are filled with zeros accordingly. Since the bits shifted out effectively represent the remainder, the
            // Overflow flag is used instead as a Rounding flag. This flag together with the Carry flag helps the user to determine whether
            // the remainder bits lost were greater than, less than or equal to one half an LSB. Only shift values between 0 and 15 are allowed.
            // When using a GPR as the count control, only the least significant 4 bits are used.
            // E: Always cleared.
            // Z: Set if result equals zero. Cleared otherwise.
            // V: Set if in any cycle of the shift operation a '1' is shifted out of the carry flag. Cleared for a shift count of zero.
            // C: The carry flag is set according to the last LSB shifted out of op1. Cleared for a shift count of zero.
            // N: Set if the most significant bit of the result is set. Cleared otherwise.

            0x6C => {
                Ok(Instruction {
                    // Rwn, Rwm
                    // Shift right direct word GPR; number of shift cycles specified by direct GPR
                    id: 0x6C,
                    mnemonic: "shr",
                    encoding: EncodingType::reg4_reg4,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: Some(OperandType::WordRegister(1)),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_SHR | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            0x7C => {
                Ok(Instruction {
                    // Rwn, #data4
                    // Shift right direct word GPR; number of shift cycles specified by immediate data
                    id: 0x7C,
                    mnemonic: "shr",
                    encoding: EncodingType::reg4_data4,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: Some(OperandType::ImmediateData4),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_SHR | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            // SRST: Software Reset
            // This instruction is used to perform a software reset. A software reset has a similar effect on the microcontroller as an
            // externally applied hardware reset.
            //
            // NOTE: To insure that this instruction is not accidentally executed, it is implemented as a protected instruction.
            // NOTE: Condition flags not affected

            0xB7 => {
                Ok(Instruction {
                    // ---
                    // Software Reset
                    id: 0xB7,
                    mnemonic: "srst",
                    encoding: EncodingType::NO_ARGS4,
                    op1: None,
                    op2: None,
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_NULL,
                    esil: "",
                })
            },

            // SRVWDT: Service Watchdog Timer
            // This instruction services the Watchdog Timer. It reloads the high order byte of the Watchdog Timer with a preset value
            // and clears the low byte on every occurrence. Once this instruction has been executed, the watchdog timer cannot be disabled.
            //
            // NOTE: To insure that this instruction is not accidentally executed, it is implemented as a protected instruction.
            // NOTE: Condition flags not affected

            0xA7 => {
                Ok(Instruction {
                    // ---
                    // Service Watchdog Timer
                    id: 0xA7,
                    mnemonic: "srvwdt",
                    encoding: EncodingType::NO_ARGS4,
                    op1: None,
                    op2: None,
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_NULL,
                    esil: "",
                })
            },

            // SUB: Integer Subtraction
            // Performs a 2's complement binary subtraction of the source operand specified by op2 from the destination operand specified
            // by op1. The result is then stored in op1.
            // E: Set if the value of op2 represents the lowest possible negative number. Cleared otherwise. Used to signal the end of a table.
            // Z: Set if result equals zero. Cleared otherwise.
            // V: Set if an arithmetic underflow occurred, i.e. the result cannot be represented in the specified data type. Cleared otherwise.
            // C: Set if a borrow is generated. Cleared otherwise.
            // N: Set if the most significant bit of the result is set. Cleared otherwise.

            0x20 => {
                Ok(Instruction {
                    // Rwn, Rwm
                    // Subtract direct word GPR from direct GPR
                    id: 0x20,
                    mnemonic: "sub",
                    encoding: EncodingType::reg4_reg4,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: Some(OperandType::WordRegister(1)),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_SUB | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            0x28 => {
                Ok(Instruction {
                    // Rwn, [Rwi]
                    // Subtract indirect word memory from direct GPR
                    // Rwn, [Rwi+]
                    // Subtract indirect word memory from direct GPR and post-increment source pointer by 2
                    // Rwn, #data3
                    // Subtract immediate word data from direct GPR
                    id: 0x28,
                    mnemonic: "sub",
                    encoding: EncodingType::reg4_or_data3,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: Some(OperandType::ImmediateData3),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_SUB,
                    esil: "",
                })
            },

            0x26 => {
                Ok(Instruction {
                    // reg, #data16
                    // Subtract immediate word data from direct register
                    id: 0x26,
                    mnemonic: "sub",
                    encoding: EncodingType::reg8_data16,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: Some(OperandType::ImmediateData16),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_SUB | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            0x22 => {
                Ok(Instruction {
                    // reg, mem
                    // Subtract direct word memory from direct register
                    id: 0x22,
                    mnemonic: "sub",
                    encoding: EncodingType::reg8_mem16,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: Some(OperandType::DirectMemory16),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_SUB | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            0x24 => {
                Ok(Instruction {
                    // mem, reg
                    // Subtract direct word register from direct memory
                    id: 0x24,
                    mnemonic: "sub",
                    encoding: EncodingType::reg8_mem16,
                    op1: Some(OperandType::DirectMemory16),
                    op2: Some(OperandType::WordRegister(0)),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_SUB | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            // SUBB: Integer Subtraction
            // Performs a 2's complement binary subtraction of the source operand specified by op2 from the destination operand specified
            // by op1. The result is then stored in op1.
            // E: Set if the value of op2 represents the lowest possible negative number. Cleared otherwise. Used to signal the end of a table.
            // Z: Set if result equals zero. Cleared otherwise.
            // V: Set if an arithmetic underflow occurred, i.e. the result cannot be represented in the specified data type. Cleared otherwise.
            // C: Set if a borrow is generated. Cleared otherwise.
            // N: Set if the most significant bit of the result is set. Cleared otherwise.

            0x21 => {
                Ok(Instruction {
                    // Rbn, Rbm
                    // Subtract direct byte GPR from direct GPR
                    id: 0x21,
                    mnemonic: "subb",
                    encoding: EncodingType::reg4_reg4,
                    op1: Some(OperandType::ByteRegister(0)),
                    op2: Some(OperandType::ByteRegister(1)),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_SUB | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            0x29 => {
                Ok(Instruction {
                    // Rbn, [Rwi]
                    // Subtract indirect byte memory from direct GPR
                    // Rbn, [Rwi+]
                    // Subtract indirect byte memory from direct GPR and post-increment source pointer by 1
                    // Rbn, #data3
                    // Subtract immediate byte data from direct GPR
                    id: 0x29,
                    mnemonic: "subb",
                    encoding: EncodingType::reg4_or_data3,
                    op1: Some(OperandType::ByteRegister(0)),
                    op2: Some(OperandType::ImmediateData3),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_SUB,
                    esil: "",
                })
            },

            0x27 => {
                Ok(Instruction {
                    // reg, #data8
                    // Subtract immediate byte data from direct register
                    id: 0x27,
                    mnemonic: "subb",
                    encoding: EncodingType::reg8_data8_nop8,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: Some(OperandType::ImmediateData8),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_SUB | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            0x23 => {
                Ok(Instruction {
                    // reg, mem
                    // Subtract direct byte memory from direct register
                    id: 0x23,
                    mnemonic: "subb",
                    encoding: EncodingType::reg8_mem16,
                    op1: Some(OperandType::ByteRegister(0)),
                    op2: Some(OperandType::DirectMemory16),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_SUB | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            0x25 => {
                Ok(Instruction {
                    // mem, reg
                    // Subtract direct byte register from direct memory
                    id: 0x25,
                    mnemonic: "subb",
                    encoding: EncodingType::reg8_mem16,
                    op1: Some(OperandType::DirectMemory16),
                    op2: Some(OperandType::ByteRegister(0)),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_SUB | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            // SUBC: Integer Subtraction with Carry
            // Performs a 2's complement binary subtraction of the source operand specified by op2 and the previously generated carry
            // bit from the destination operand specified by op1. The result is then stored in op1. This instruction can be used to
            // perform multiple precision arithmetic.
            // E: Set if the value of op2 represents the lowest possible negative number. Cleared otherwise. Used to signal the end of a table.
            // Z: Set if result equals zero and the previous Z flag was set. Cleared otherwise.
            // V: Set if an arithmetic underflow occurred, i.e. the result cannot be represented in the specified data type. Cleared otherwise.
            // C: Set if a borrow is generated. Cleared otherwise.
            // N: Set if the most significant bit of the result is set. Cleared otherwise.

            0x30 => {
                Ok(Instruction {
                    // Rwn, Rwm
                    // Subtract direct word GPR from direct GPR with Carry
                    id: 0x30,
                    mnemonic: "subc",
                    encoding: EncodingType::reg4_reg4,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: Some(OperandType::WordRegister(1)),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_SUB | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            0x38 => {
                Ok(Instruction {
                    // Rwn, [Rwi]
                    // Subtract indirect word memory from direct GPR with Carry
                    // Rwn, [Rwi+]
                    // Subtract indirect word memory from direct GPR with Carry and post-increment source pointer by 2
                    // Rwn, #data3
                    // Subtract immediate word data from direct GPR with Carry
                    id: 0x38,
                    mnemonic: "subc",
                    encoding: EncodingType::reg4_or_data3,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: Some(OperandType::ImmediateData3),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_SUB,
                    esil: "",
                })
            },

            0x36 => {
                Ok(Instruction {
                    // reg, #data16
                    // Subtract immediate word data from direct register with Carry
                    id: 0x36,
                    mnemonic: "subc",
                    encoding: EncodingType::reg8_data16,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: Some(OperandType::ImmediateData16),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_SUB | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            0x32 => {
                Ok(Instruction {
                    // reg, mem
                    // Subtract direct word memory from direct register with Carry
                    id: 0x32,
                    mnemonic: "subc",
                    encoding: EncodingType::reg8_mem16,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: Some(OperandType::DirectMemory16),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_SUB | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            0x34 => {
                Ok(Instruction {
                    // mem, reg
                    // Subtract direct word register from direct memory with Carry
                    id: 0x34,
                    mnemonic: "subc",
                    encoding: EncodingType::reg8_mem16,
                    op1: Some(OperandType::DirectMemory16),
                    op2: Some(OperandType::WordRegister(0)),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_SUB | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            // SUBCB: Integer Subtraction with Carry
            // Performs a 2's complement binary subtraction of the source operand specified by op2 and the previously generated
            // carry bit from the destination operand specified by op1. The result is then stored in op1. This instruction can
            // be used to perform multiple precision arithmetic.
            // E: Set if the value of op2 represents the lowest possible negative number. Cleared otherwise. Used to signal the end of a table.
            // Z: Set if result equals zero and the previous Z flag was set. Cleared otherwise.
            // V: Set if an arithmetic underflow occurred, i.e. the result cannot be represented in the specified data type. Cleared otherwise.
            // C: Set if a borrow is generated. Cleared otherwise.
            // N: Set if the most significant bit of the result is set. Cleared otherwise.

            0x31 => {
                Ok(Instruction {
                    // Rbn, Rbm
                    // Subtract direct byte GPR from direct GPR with Carry
                    id: 0x31,
                    mnemonic: "subcb",
                    encoding: EncodingType::reg4_reg4,
                    op1: Some(OperandType::ByteRegister(0)),
                    op2: Some(OperandType::ByteRegister(1)),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_SUB | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            0x39 => {
                Ok(Instruction {
                    // Rbn, [Rwi]
                    // Subtract indirect byte memory from direct GPR with Carry
                    // Rbn, [Rwi+]
                    // Subtract indirect byte memory from direct GPR with Carry and post-increment source pointer by 1
                    // Rbn, #data3
                    // Subtract immediate byte data from direct GPR with Carry
                    id: 0x39,
                    mnemonic: "subcb",
                    encoding: EncodingType::reg4_or_data3,
                    op1: Some(OperandType::ByteRegister(0)),
                    op2: Some(OperandType::ImmediateData3),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_SUB,
                    esil: "",
                })
            },

            0x37 => {
                Ok(Instruction {
                    // reg, #data8
                    // Subtract immediate byte data from direct register with Carry
                    id: 0x37,
                    mnemonic: "subcb",
                    encoding: EncodingType::reg8_data8_nop8,
                    op1: Some(OperandType::ByteRegister(0)),
                    op2: Some(OperandType::ImmediateData8),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_SUB | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            0x33 => {
                Ok(Instruction {
                    // reg, mem
                    // Subtract direct byte memory from direct register with Carry
                    id: 0x33,
                    mnemonic: "subcb",
                    encoding: EncodingType::reg8_mem16,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: Some(OperandType::DirectMemory16),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_SUB | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            0x35 => {
                Ok(Instruction {
                    // mem, reg
                    // Subtract direct byte register from direct memory with Carry
                    id: 0x35,
                    mnemonic: "subcb",
                    encoding: EncodingType::reg8_mem16,
                    op1: Some(OperandType::DirectMemory16),
                    op2: Some(OperandType::ByteRegister(0)),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_SUB | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            // TRAP: Software Trap
            // Invokes a trap or interrupt routine based on the specified operand, op1. The invoked routine is determined by branching
            // to the specified vector table entry point. This routine has no indication of whether it was called by software or hardware.
            // System state is preserved identically to hardware interrupt entry except that the CPU priority level is not affected. The
            // RETI, return from interrupt, instruction is used to resume execution after the trap or interrupt routine has completed. The
            // CSP is pushed if segmentation is enabled. This is indicated by the SGTDIS bit in the SYSCON register.
            //
            // NOTE: Condition flags not affected

            0x9B => {
                Ok(Instruction {
                    // #trap7
                    // Call interrupt service routine via immediate trap number
                    id: 0x9B,
                    mnemonic: "trap",
                    encoding: EncodingType::trap7,
                    op1: Some(OperandType::ImmediateTrap7),
                    op2: None,
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_TRAP,
                    esil: "",
                })
            },

            // XOR: Logical Exclusive OR
            // Performs a bitwise logical EXCLUSIVE OR of the source operand specified by op2 and the destination operand specified by op1. The
            // result is then stored in op1.
            // E: Set if the value of op2 represents the lowest possible negative number. Cleared otherwise. Used to signal the end of a table.
            // Z: Set if result equals zero. Cleared otherwise.
            // V: Always cleared.
            // C: Always cleared.
            // N: Set if the most significant bit of the result is set. Cleared otherwise.

            0x50 => {
                Ok(Instruction {
                    // Rwn, Rwm
                    // Bitwise XOR direct word GPR with direct GPR
                    id: 0x50,
                    mnemonic: "xor",
                    encoding: EncodingType::reg4_reg4,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: Some(OperandType::WordRegister(1)),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_XOR | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            0x58 => {
                Ok(Instruction {
                    // Rwn, [Rwi]
                    // Bitwise XOR indirect word memory with direct GPR
                    // Rwn, [Rwi+]
                    // Bitwise XOR indirect word memory with direct GPR and post-increment source pointer by 2
                    // Rwn, #data3
                    // Bitwise XOR immediate word data with direct GPR
                    id: 0x58,
                    mnemonic: "xor",
                    encoding: EncodingType::reg4_or_data3,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: Some(OperandType::ImmediateData3),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_XOR,
                    esil: "",
                })
            },

            0x56 => {
                Ok(Instruction {
                    // reg, #data16
                    // Bitwise XOR immediate word data with direct register
                    id: 0x56,
                    mnemonic: "xor",
                    encoding: EncodingType::reg8_data16,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: Some(OperandType::ImmediateData16),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_XOR | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            0x52 => {
                Ok(Instruction {
                    // reg, mem
                    // Bitwise XOR direct word memory with direct register
                    id: 0x52,
                    mnemonic: "xor",
                    encoding: EncodingType::reg8_mem16,
                    op1: Some(OperandType::WordRegister(0)),
                    op2: Some(OperandType::DirectMemory16),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_XOR | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            0x54 => {
                Ok(Instruction {
                    // mem, reg
                    // Bitwise XOR direct word register with direct memory
                    id: 0x54,
                    mnemonic: "xor",
                    encoding: EncodingType::reg8_mem16,
                    op1: Some(OperandType::DirectMemory16),
                    op2: Some(OperandType::WordRegister(0)),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_XOR | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            // XORB: Logical Exclusive OR
            // Performs a bitwise logical EXCLUSIVE OR of the source operand specified by op2 and the destination operand specified by
            // op1. The result is then stored in op1.
            // E: Set if the value of op2 represents the lowest possible negative number. Cleared otherwise. Used to signal the end of a table.
            // Z: Set if result equals zero. Cleared otherwise.
            // V: Always cleared.
            // C: Always cleared.
            // N: Set if the most significant bit of the result is set. Cleared otherwise.

            0x51 => {
                Ok(Instruction {
                    // Rbn, Rbm
                    // Bitwise XOR direct byte GPR with direct GPR
                    id: 0x51,
                    mnemonic: "xorb",
                    encoding: EncodingType::reg4_reg4,
                    op1: Some(OperandType::ByteRegister(0)),
                    op2: Some(OperandType::ByteRegister(1)),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_XOR | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            0x59 => {
                Ok(Instruction {
                    // Rbn, [Rwi]
                    // Bitwise XOR indirect byte memory with direct GPR
                    // Rbn, [Rwi+]
                    // Bitwise XOR indirect byte memory with direct GPR and post-increment source pointer by 1
                    // Rbn, #data3
                    // Bitwise XOR immediate byte data with direct GPR
                    id: 0x59,
                    mnemonic: "xorb",
                    encoding: EncodingType::reg4_or_data3,
                    op1: Some(OperandType::ByteRegister(0)),
                    op2: Some(OperandType::ImmediateData3),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_XOR,
                    esil: "",
                })
            },

            0x57 => {
                Ok(Instruction {
                    // reg, #data8
                    // Bitwise XOR immediate byte data with direct register
                    id: 0x57,
                    mnemonic: "xorb",
                    encoding: EncodingType::reg8_data8_nop8,
                    op1: Some(OperandType::ByteRegister(0)),
                    op2: Some(OperandType::ImmediateData8),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_XOR | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            0x53 => {
                Ok(Instruction {
                    // reg, mem
                    // Bitwise XOR direct byte memory with direct register
                    id: 0x53,
                    mnemonic: "xorb",
                    encoding: EncodingType::reg8_mem16,
                    op1: Some(OperandType::ByteRegister(0)),
                    op2: Some(OperandType::DirectMemory16),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_XOR | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },

            0x55 => {
                Ok(Instruction {
                    // mem, reg
                    // Bitwise XOR direct byte register with direct memory
                    id: 0x55,
                    mnemonic: "xorb",
                    encoding: EncodingType::reg8_mem16,
                    op1: Some(OperandType::DirectMemory16),
                    op2: Some(OperandType::ByteRegister(0)),
                    op3: None,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_XOR | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                })
            },
            _ => {
                Err("Unknown opcode")
            }
        }
    }
}

impl<'a> TryFrom<&'a [u8]> for Instruction<'a> {
    type Error = &'a str;

    fn try_from(bytes: &[u8]) -> Result<Instruction, &'a str> {
        Instruction::try_from(bytes[0])
    }
}
