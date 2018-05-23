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

use ::r2::_RAnalOpType;

use ::encoding::EncodingType;

#[derive(PartialEq)]
pub enum InstructionParameter {
    None,
    Address,
    Bit0,
    Bit1,
    BitOffset0,
    BitOffset1,
    Condition,
    Data,
    IRange,
    Mask,
    Memory,
    Mnemonic,
    PageOrSegment,
    Register0,
    Register1,
    RelativeAddress,
    Segment,
    SubOp,
    Trap
}

bitflags! {
    pub struct InstructionParameterType : u32 {
        const NONE              = 0b00000000000000000000;
        const GENERAL_REGISTER  = 0b00000000000000000001;
        const SPECIAL_REGISTER  = 0b00000000000000000010;
        const WORD_REGISTER     = 0b00000000000000000100;
        const BYTE_REGISTER     = 0b00000000000000001000;
        const DIRECT_MEMORY     = 0b00000000000000010000;
        const INDIRECT          = 0b00000000000000100000;
        const INCREMENT         = 0b00000000000001000000;
        const DECREMENT         = 0b00000000000010000000;
        const IMMEDIATE         = 0b00000000000100000000;
        const DATA_3            = 0b00000000001000000000;
        const DATA_4            = 0b00000000010000000000;
        const DATA_8            = 0b00000000100000000000;
        const DATA_16           = 0b00000001000000000000;
        const BIT_OFFSET        = 0b00000010000000000000;
        const BIT_OFFSET_BIT    = 0b00000100000000000000;
        const BIT_OFFSET_MASK   = 0b00001000000000000000;
        const TRAP              = 0b00010000000000000000;
        const CONDITION         = 0b00100000000000000000;
        const SEGMENT           = 0b01000000000000000000;
    }
}

pub struct Instruction<'a> {
    pub id: u8,
    pub mnemonic: &'static str,
    pub encoding: EncodingType,
    pub r2_op_type: _RAnalOpType,
    pub esil: &'a str,
    pub src_param : InstructionParameter,
    pub src_type : InstructionParameterType,
    pub dst_param : InstructionParameter,
    pub dst_type : InstructionParameterType
}

impl<'a> Instruction<'a> {
    pub fn from_addr_array(bytes: &[u8]) -> Result<Instruction, String> {
        let raw_opcode = bytes[0];

        match raw_opcode {
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
                    encoding: EncodingType::nm,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_ADD | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Register1,
                    src_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER
                })
            },

            0x02 => {
                Ok(Instruction {
                    // reg, mem
                    // Add direct word memory to direct register
                    id: 0x02,
                    mnemonic: "add",
                    encoding: EncodingType::RR_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_ADD | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Memory,
                    src_type: InstructionParameterType::DIRECT_MEMORY,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::SPECIAL_REGISTER | InstructionParameterType::WORD_REGISTER
                })
            },

            0x04 => {
                Ok(Instruction {
                    // mem, reg
                    // Add direct word register to direct memory
                    id: 0x04,
                    mnemonic: "add",
                    encoding: EncodingType::RR_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_ADD | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Register0,
                    src_type: InstructionParameterType::SPECIAL_REGISTER | InstructionParameterType::WORD_REGISTER,
                    dst_param: InstructionParameter::Memory,
                    dst_type: InstructionParameterType::DIRECT_MEMORY
                })
            },

            0x06 => {
                Ok(Instruction {
                    // reg, #data16
                    // Add immediate word data to direct register
                    id: 0x06,
                    mnemonic: "add",
                    encoding: EncodingType::RR_II_II,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_ADD | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Data,
                    src_type: InstructionParameterType::IMMEDIATE | InstructionParameterType::DATA_16,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::SPECIAL_REGISTER | InstructionParameterType::WORD_REGISTER
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
                    encoding: EncodingType::data3_or_reg,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_ADD,
                    esil: "",
                    src_param: InstructionParameter::None,
                    src_type: InstructionParameterType::DATA_3 | InstructionParameterType::WORD_REGISTER,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::NONE
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
                    encoding: EncodingType::nm,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_ADD | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Register1,
                    src_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::BYTE_REGISTER,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::BYTE_REGISTER
                })
            },

            0x03 => {
                Ok(Instruction {
                    // reg, mem
                    // Add direct byte memory to direct register
                    id: 0x03,
                    mnemonic: "addb",
                    encoding: EncodingType::RR_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_ADD | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Memory,
                    src_type: InstructionParameterType::DIRECT_MEMORY,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::SPECIAL_REGISTER | InstructionParameterType::BYTE_REGISTER
                })
            },

            0x05 => {
                Ok(Instruction {
                    // mem, reg
                    // Add direct byte register to direct memory
                    id: 0x05,
                    mnemonic: "addb",
                    encoding: EncodingType::RR_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_ADD | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Register0,
                    src_type: InstructionParameterType::SPECIAL_REGISTER | InstructionParameterType::BYTE_REGISTER,
                    dst_param: InstructionParameter::Memory,
                    dst_type: InstructionParameterType::DIRECT_MEMORY
                })
            },

            0x07 => {
                Ok(Instruction {
                    // reg, #data8
                    // Add immediate byte data to direct register
                    id: 0x07,
                    mnemonic: "addb",
                    encoding: EncodingType::RR_II_xx,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_ADD | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Data,
                    src_type: InstructionParameterType::IMMEDIATE | InstructionParameterType::DATA_8,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::SPECIAL_REGISTER | InstructionParameterType::BYTE_REGISTER
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
                    encoding: EncodingType::data3_or_reg,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_ADD,
                    esil: "",
                    src_param: InstructionParameter::None,
                    src_type: InstructionParameterType::DATA_3 | InstructionParameterType::BYTE_REGISTER,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::NONE
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
                    encoding: EncodingType::nm,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_ADD | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Register1,
                    src_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::GENERAL_REGISTER |InstructionParameterType::WORD_REGISTER
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
                    encoding: EncodingType::data3_or_reg,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_ADD,
                    esil: "",
                    src_param: InstructionParameter::None,
                    src_type: InstructionParameterType::DATA_3 | InstructionParameterType::WORD_REGISTER,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::NONE
                })
            },

            0x16 => {
                Ok(Instruction {
                    // reg, #data16
                    // Add immediate word data to direct register with Carry
                    id: 0x16,
                    mnemonic: "addc",
                    encoding: EncodingType::RR_II_II,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_ADD | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Data,
                    src_type: InstructionParameterType::IMMEDIATE | InstructionParameterType::DATA_16,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::SPECIAL_REGISTER | InstructionParameterType::WORD_REGISTER
                })
            },

            0x12 => {
                Ok(Instruction {
                    // reg, mem
                    // Add direct word memory to direct register with Carry
                    id: 0x12,
                    mnemonic: "addc",
                    encoding: EncodingType::RR_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_ADD | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Memory,
                    src_type: InstructionParameterType::DIRECT_MEMORY,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::SPECIAL_REGISTER | InstructionParameterType::WORD_REGISTER
                })
            },

            0x14 => {
                Ok(Instruction {
                    // mem, reg
                    // Add direct word register to direct memory with Carry
                    id: 0x14,
                    mnemonic: "addc",
                    encoding: EncodingType::RR_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_ADD | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Register0,
                    src_type: InstructionParameterType::SPECIAL_REGISTER | InstructionParameterType::WORD_REGISTER,
                    dst_param: InstructionParameter::Memory,
                    dst_type: InstructionParameterType::DIRECT_MEMORY
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
                    encoding: EncodingType::nm,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_ADD | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Register1,
                    src_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::BYTE_REGISTER,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::BYTE_REGISTER
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
                    encoding: EncodingType::data3_or_reg,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_ADD,
                    esil: "",
                    src_param: InstructionParameter::None,
                    src_type: InstructionParameterType::DATA_3 | InstructionParameterType::BYTE_REGISTER,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::NONE
                })
            },

            0x17 => {
                Ok(Instruction {
                    // reg, #data8
                    // Add immediate byte data to direct register with Carry
                    id: 0x17,
                    mnemonic: "addcb",
                    encoding: EncodingType::RR_II_xx,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_ADD | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Data,
                    src_type: InstructionParameterType::IMMEDIATE | InstructionParameterType::DATA_8,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::SPECIAL_REGISTER | InstructionParameterType::BYTE_REGISTER
                })
            },

            0x13 => {
                Ok(Instruction {
                    // reg, mem
                    // Add direct byte memory to direct register with Carry
                    id: 0x13,
                    mnemonic: "addcb",
                    encoding: EncodingType::RR_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_ADD | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Memory,
                    src_type: InstructionParameterType::DIRECT_MEMORY,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::SPECIAL_REGISTER | InstructionParameterType::BYTE_REGISTER
                })
            },

            0x15 => {
                Ok(Instruction {
                    // mem, reg
                    // Add direct byte register to direct memory with Carry
                    id: 0x15,
                    mnemonic: "addcb",
                    encoding: EncodingType::RR_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_ADD | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Register0,
                    src_type: InstructionParameterType::SPECIAL_REGISTER | InstructionParameterType::BYTE_REGISTER,
                    dst_param: InstructionParameter::Memory,
                    dst_type: InstructionParameterType::DIRECT_MEMORY
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
                    encoding: EncodingType::nm,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_AND | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "{reg1},NUM,{reg0},&=",
                    src_param: InstructionParameter::Register1,
                    src_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER
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
                    encoding: EncodingType::data3_or_reg,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_AND,
                    esil: "",
                    src_param: InstructionParameter::None,
                    src_type: InstructionParameterType::DATA_3 | InstructionParameterType::WORD_REGISTER,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::NONE
                })
            },

            0x66 => {
                Ok(Instruction {
                    // reg, #data16
                    // Bitwise AND immediate word data with direct register
                    id: 0x66,
                    mnemonic: "and",
                    encoding: EncodingType::RR_II_II,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_AND | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "{immed},{reg0},&=",
                    src_param: InstructionParameter::Data,
                    src_type: InstructionParameterType::IMMEDIATE | InstructionParameterType::DATA_16,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::SPECIAL_REGISTER | InstructionParameterType::WORD_REGISTER
                })
            },

            0x62 => {
                Ok(Instruction {
                    // reg, mem
                    // Bitwise AND direct word memory with direct register
                    id: 0x62,
                    mnemonic: "and",
                    encoding: EncodingType::RR_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_AND | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Memory,
                    src_type: InstructionParameterType::DIRECT_MEMORY,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::SPECIAL_REGISTER | InstructionParameterType::WORD_REGISTER
                })
            },

            0x64 => {
                Ok(Instruction {
                    // mem, reg
                    // Bitwise AND direct word register with direct memory
                    id: 0x64,
                    mnemonic: "and",
                    encoding: EncodingType::RR_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_AND | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Register0,
                    src_type: InstructionParameterType::SPECIAL_REGISTER | InstructionParameterType::WORD_REGISTER,
                    dst_param: InstructionParameter::Memory,
                    dst_type: InstructionParameterType::DIRECT_MEMORY
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
                    encoding: EncodingType::nm,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_AND | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Register1,
                    src_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::BYTE_REGISTER,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::BYTE_REGISTER
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
                    encoding: EncodingType::data3_or_reg,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_AND,
                    esil: "",
                    src_param: InstructionParameter::None,
                    src_type: InstructionParameterType::DATA_3 | InstructionParameterType::BYTE_REGISTER,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::NONE
                })
            },

            0x67 => {
                Ok(Instruction {
                    // reg, #data8
                    // Bitwise AND immediate byte data with direct register
                    id: 0x67,
                    mnemonic: "andb",
                    encoding: EncodingType::RR_II_xx,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_AND | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Data,
                    src_type: InstructionParameterType::IMMEDIATE | InstructionParameterType::DATA_8,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::SPECIAL_REGISTER | InstructionParameterType::BYTE_REGISTER
                })
            },

            0x63 => {
                Ok(Instruction {
                    // reg, mem
                    // Bitwise AND direct byte memory with direct register
                    id: 0x63,
                    mnemonic: "andb",
                    encoding: EncodingType::RR_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_AND | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Memory,
                    src_type: InstructionParameterType::DIRECT_MEMORY,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::SPECIAL_REGISTER | InstructionParameterType::BYTE_REGISTER
                })
            },

            0x65 => {
                Ok(Instruction {
                    // mem, reg
                    // Bitwise AND direct byte register with direct memory
                    id: 0x65,
                    mnemonic: "andb",
                    encoding: EncodingType::RR_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_AND | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Register0,
                    src_type: InstructionParameterType::SPECIAL_REGISTER | InstructionParameterType::BYTE_REGISTER,
                    dst_param: InstructionParameter::Memory,
                    dst_type: InstructionParameterType::DIRECT_MEMORY
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
                    encoding: EncodingType::nm,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_SHR | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Register1,
                    src_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER
                })
            },

            0xBC => {
                Ok(Instruction {
                    // Rwn, #data4
                    // Arithmetic (sign bit) shift right direct word GPR; number of shift cycles specified by immediate data
                    id: 0xBC,
                    mnemonic: "ashr",
                    encoding: EncodingType::In,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_SHR | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Data,
                    src_type: InstructionParameterType::IMMEDIATE | InstructionParameterType::DATA_4,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER
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
                    encoding: EncodingType::atomic_extr,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_NULL,
                    esil: "",
                    src_param: InstructionParameter::IRange,
                    src_type: InstructionParameterType::IMMEDIATE,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::NONE
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
                    encoding: EncodingType::QQ_ZZ_qz,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_AND,
                    esil: "",
                    src_param: InstructionParameter::BitOffset1,
                    src_type: InstructionParameterType::BIT_OFFSET | InstructionParameterType::BIT_OFFSET_BIT,
                    dst_param: InstructionParameter::BitOffset0,
                    dst_type: InstructionParameterType::BIT_OFFSET | InstructionParameterType::BIT_OFFSET_BIT
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
                    encoding: EncodingType::q_QQ,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_AND,
                    esil: "",
                    src_param: InstructionParameter::BitOffset0,
                    src_type: InstructionParameterType::BIT_OFFSET | InstructionParameterType::BIT_OFFSET_BIT,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::NONE
                })
            },

            0x1E => {
                Ok(Instruction {
                    // bitaddrQ.q
                    // Clear direct bit
                    id: 0x1E,
                    mnemonic: "bclr",
                    encoding: EncodingType::q_QQ,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_AND,
                    esil: "",
                    src_param: InstructionParameter::BitOffset0,
                    src_type: InstructionParameterType::BIT_OFFSET | InstructionParameterType::BIT_OFFSET_BIT,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::NONE
                })
            },

            0x2E => {
                Ok(Instruction {
                    // bitaddrQ.q
                    // Clear direct bit
                    id: 0x2E,
                    mnemonic: "bclr",
                    encoding: EncodingType::q_QQ,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_AND,
                    esil: "",
                    src_param: InstructionParameter::BitOffset0,
                    src_type: InstructionParameterType::BIT_OFFSET | InstructionParameterType::BIT_OFFSET_BIT,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::NONE
                })
            },

            0x3E => {
                Ok(Instruction {
                    // bitaddrQ.q
                    // Clear direct bit
                    id: 0x3E,
                    mnemonic: "bclr",
                    encoding: EncodingType::q_QQ,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_AND,
                    esil: "",
                    src_param: InstructionParameter::BitOffset0,
                    src_type: InstructionParameterType::BIT_OFFSET | InstructionParameterType::BIT_OFFSET_BIT,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::NONE
                })
            },

            0x4E => {
                Ok(Instruction {
                    // bitaddrQ.q
                    // Clear direct bit
                    id: 0x4E,
                    mnemonic: "bclr",
                    encoding: EncodingType::q_QQ,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_AND,
                    esil: "",
                    src_param: InstructionParameter::BitOffset0,
                    src_type: InstructionParameterType::BIT_OFFSET | InstructionParameterType::BIT_OFFSET_BIT,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::NONE
                })
            },

            0x5E => {
                Ok(Instruction {
                    // bitaddrQ.q
                    // Clear direct bit
                    id: 0x5E,
                    mnemonic: "bclr",
                    encoding: EncodingType::q_QQ,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_AND,
                    esil: "",
                    src_param: InstructionParameter::BitOffset0,
                    src_type: InstructionParameterType::BIT_OFFSET | InstructionParameterType::BIT_OFFSET_BIT,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::NONE
                })
            },

            0x6E => {
                Ok(Instruction {
                    // bitaddrQ.q
                    // Clear direct bit
                    id: 0x6E,
                    mnemonic: "bclr",
                    encoding: EncodingType::q_QQ,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_AND,
                    esil: "",
                    src_param: InstructionParameter::BitOffset0,
                    src_type: InstructionParameterType::BIT_OFFSET | InstructionParameterType::BIT_OFFSET_BIT,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::NONE
                })
            },

            0x7E => {
                Ok(Instruction {
                    // bitaddrQ.q
                    // Clear direct bit
                    id: 0x7E,
                    mnemonic: "bclr",
                    encoding: EncodingType::q_QQ,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_AND,
                    esil: "",
                    src_param: InstructionParameter::BitOffset0,
                    src_type: InstructionParameterType::BIT_OFFSET | InstructionParameterType::BIT_OFFSET_BIT,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::NONE
                })
            },

            0x8E => {
                Ok(Instruction {
                    // bitaddrQ.q
                    // Clear direct bit
                    id: 0x8E,
                    mnemonic: "bclr",
                    encoding: EncodingType::q_QQ,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_AND,
                    esil: "",
                    src_param: InstructionParameter::BitOffset0,
                    src_type: InstructionParameterType::BIT_OFFSET | InstructionParameterType::BIT_OFFSET_BIT,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::NONE
                })
            },

            0x9E => {
                Ok(Instruction {
                    // bitaddrQ.q
                    // Clear direct bit
                    id: 0x9E,
                    mnemonic: "bclr",
                    encoding: EncodingType::q_QQ,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_AND,
                    esil: "",
                    src_param: InstructionParameter::BitOffset0,
                    src_type: InstructionParameterType::BIT_OFFSET | InstructionParameterType::BIT_OFFSET_BIT,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::NONE
                })
            },

            0xAE => {
                Ok(Instruction {
                    // bitaddrQ.q
                    // Clear direct bit
                    id: 0xAE,
                    mnemonic: "bclr",
                    encoding: EncodingType::q_QQ,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_AND,
                    esil: "",
                    src_param: InstructionParameter::BitOffset0,
                    src_type: InstructionParameterType::BIT_OFFSET | InstructionParameterType::BIT_OFFSET_BIT,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::NONE
                })
            },

            0xBE => {
                Ok(Instruction {
                    // bitaddrQ.q
                    // Clear direct bit
                    id: 0xBE,
                    mnemonic: "bclr",
                    encoding: EncodingType::q_QQ,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_AND,
                    esil: "",
                    src_param: InstructionParameter::BitOffset0,
                    src_type: InstructionParameterType::BIT_OFFSET | InstructionParameterType::BIT_OFFSET_BIT,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::NONE
                })
            },

            0xCE => {
                Ok(Instruction {
                    // bitaddrQ.q
                    // Clear direct bit
                    id: 0xCE,
                    mnemonic: "bclr",
                    encoding: EncodingType::q_QQ,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_AND,
                    esil: "",
                    src_param: InstructionParameter::BitOffset0,
                    src_type: InstructionParameterType::BIT_OFFSET | InstructionParameterType::BIT_OFFSET_BIT,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::NONE
                })
            },

            0xDE => {
                Ok(Instruction {
                    // bitaddrQ.q
                    // Clear direct bit
                    id: 0xDE,
                    mnemonic: "bclr",
                    encoding: EncodingType::q_QQ,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_AND,
                    esil: "",
                    src_param: InstructionParameter::BitOffset0,
                    src_type: InstructionParameterType::BIT_OFFSET | InstructionParameterType::BIT_OFFSET_BIT,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::NONE
                })
            },

            0xEE => {
                Ok(Instruction {
                    // bitaddrQ.q
                    // Clear direct bit
                    id: 0xEE,
                    mnemonic: "bclr",
                    encoding: EncodingType::q_QQ,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_AND,
                    esil: "",
                    src_param: InstructionParameter::BitOffset0,
                    src_type: InstructionParameterType::BIT_OFFSET | InstructionParameterType::BIT_OFFSET_BIT,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::NONE
                })
            },

            0xFE => {
                Ok(Instruction {
                    // bitaddrQ.q
                    // Clear direct bit
                    id: 0xFE,
                    mnemonic: "bclr",
                    encoding: EncodingType::q_QQ,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_AND,
                    esil: "",
                    src_param: InstructionParameter::BitOffset0,
                    src_type: InstructionParameterType::BIT_OFFSET | InstructionParameterType::BIT_OFFSET_BIT,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::NONE
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
                    encoding: EncodingType::QQ_ZZ_qz,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CMP,
                    esil: "",
                    src_param: InstructionParameter::BitOffset1,
                    src_type: InstructionParameterType::BIT_OFFSET | InstructionParameterType::BIT_OFFSET_BIT,
                    dst_param: InstructionParameter::BitOffset0,
                    dst_type: InstructionParameterType::BIT_OFFSET | InstructionParameterType::BIT_OFFSET_BIT
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
                    encoding: EncodingType::QQ_AA_II,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_NULL,
                    esil: "",
                    src_param: InstructionParameter::Data,
                    src_type: InstructionParameterType::IMMEDIATE | InstructionParameterType::DATA_8,
                    dst_param: InstructionParameter::BitOffset0,
                    dst_type: InstructionParameterType::BIT_OFFSET | InstructionParameterType::BIT_OFFSET_MASK
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
                    encoding: EncodingType::QQ_AA_II,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_NULL,
                    esil: "",
                    src_param: InstructionParameter::Data,
                    src_type: InstructionParameterType::IMMEDIATE | InstructionParameterType::DATA_8,
                    dst_param: InstructionParameter::BitOffset0,
                    dst_type: InstructionParameterType::BIT_OFFSET | InstructionParameterType::BIT_OFFSET_MASK
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
                    encoding: EncodingType::QQ_ZZ_qz,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV,
                    esil: "",
                    src_param: InstructionParameter::BitOffset1,
                    src_type: InstructionParameterType::BIT_OFFSET | InstructionParameterType::BIT_OFFSET_BIT,
                    dst_param: InstructionParameter::BitOffset0,
                    dst_type: InstructionParameterType::BIT_OFFSET | InstructionParameterType::BIT_OFFSET_BIT
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
                    encoding: EncodingType::QQ_ZZ_qz,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV,
                    esil: "",
                    src_param: InstructionParameter::BitOffset1,
                    src_type: InstructionParameterType::BIT_OFFSET | InstructionParameterType::BIT_OFFSET_BIT,
                    dst_param: InstructionParameter::BitOffset0,
                    dst_type: InstructionParameterType::BIT_OFFSET | InstructionParameterType::BIT_OFFSET_BIT
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
                    encoding: EncodingType::QQ_ZZ_qz,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_OR,
                    esil: "",
                    src_param: InstructionParameter::BitOffset1,
                    src_type: InstructionParameterType::BIT_OFFSET | InstructionParameterType::BIT_OFFSET_BIT,
                    dst_param: InstructionParameter::BitOffset0,
                    dst_type: InstructionParameterType::BIT_OFFSET | InstructionParameterType::BIT_OFFSET_BIT
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
                    id: 0x0F,
                    mnemonic: "bset",
                    encoding: EncodingType::q_QQ,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_OR,
                    esil: "",
                    src_param: InstructionParameter::BitOffset0,
                    src_type: InstructionParameterType::BIT_OFFSET | InstructionParameterType::BIT_OFFSET_BIT,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::NONE
                })
            },

            0x1F => {
                Ok(Instruction {
                    id: 0x1F,
                    mnemonic: "bset",
                    encoding: EncodingType::q_QQ,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_OR,
                    esil: "",
                    src_param: InstructionParameter::BitOffset0,
                    src_type: InstructionParameterType::BIT_OFFSET | InstructionParameterType::BIT_OFFSET_BIT,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::NONE
                })
            },

            0x2F => {
                Ok(Instruction {
                    id: 0x2F,
                    mnemonic: "bset",
                    encoding: EncodingType::q_QQ,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_OR,
                    esil: "",
                    src_param: InstructionParameter::BitOffset0,
                    src_type: InstructionParameterType::BIT_OFFSET | InstructionParameterType::BIT_OFFSET_BIT,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::NONE
                })
            },

            0x3F => {
                Ok(Instruction {
                    id: 0x3F,
                    mnemonic: "bset",
                    encoding: EncodingType::q_QQ,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_OR,
                    esil: "",
                    src_param: InstructionParameter::BitOffset0,
                    src_type: InstructionParameterType::BIT_OFFSET | InstructionParameterType::BIT_OFFSET_BIT,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::NONE
                })
            },

            0x4F => {
                Ok(Instruction {
                    id: 0x4F,
                    mnemonic: "bset",
                    encoding: EncodingType::q_QQ,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_OR,
                    esil: "",
                    src_param: InstructionParameter::BitOffset0,
                    src_type: InstructionParameterType::BIT_OFFSET | InstructionParameterType::BIT_OFFSET_BIT,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::NONE
                })
            },

            0x5F => {
                Ok(Instruction {
                    id: 0x5F,
                    mnemonic: "bset",
                    encoding: EncodingType::q_QQ,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_OR,
                    esil: "",
                    src_param: InstructionParameter::BitOffset0,
                    src_type: InstructionParameterType::BIT_OFFSET | InstructionParameterType::BIT_OFFSET_BIT,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::NONE
                })
            },

            0x6F => {
                Ok(Instruction {
                    id: 0x6F,
                    mnemonic: "bset",
                    encoding: EncodingType::q_QQ,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_OR,
                    esil: "",
                    src_param: InstructionParameter::BitOffset0,
                    src_type: InstructionParameterType::BIT_OFFSET | InstructionParameterType::BIT_OFFSET_BIT,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::NONE
                })
            },

            0x7F => {
                Ok(Instruction {
                    id: 0x7F,
                    mnemonic: "bset",
                    encoding: EncodingType::q_QQ,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_OR,
                    esil: "",
                    src_param: InstructionParameter::BitOffset0,
                    src_type: InstructionParameterType::BIT_OFFSET | InstructionParameterType::BIT_OFFSET_BIT,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::NONE
                })
            },

            0x8F => {
                Ok(Instruction {
                    id: 0x8F,
                    mnemonic: "bset",
                    encoding: EncodingType::q_QQ,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_OR,
                    esil: "",
                    src_param: InstructionParameter::BitOffset0,
                    src_type: InstructionParameterType::BIT_OFFSET | InstructionParameterType::BIT_OFFSET_BIT,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::NONE
                })
            },

            0x9F => {
                Ok(Instruction {
                    id: 0x9F,
                    mnemonic: "bset",
                    encoding: EncodingType::q_QQ,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_OR,
                    esil: "",
                    src_param: InstructionParameter::BitOffset0,
                    src_type: InstructionParameterType::BIT_OFFSET | InstructionParameterType::BIT_OFFSET_BIT,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::NONE
                })
            },

            0xAF => {
                Ok(Instruction {
                    id: 0xAF,
                    mnemonic: "bset",
                    encoding: EncodingType::q_QQ,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_OR,
                    esil: "",
                    src_param: InstructionParameter::BitOffset0,
                    src_type: InstructionParameterType::BIT_OFFSET | InstructionParameterType::BIT_OFFSET_BIT,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::NONE
                })
            },

            0xBF => {
                Ok(Instruction {
                    id: 0xBF,
                    mnemonic: "bset",
                    encoding: EncodingType::q_QQ,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_OR,
                    esil: "",
                    src_param: InstructionParameter::BitOffset0,
                    src_type: InstructionParameterType::BIT_OFFSET | InstructionParameterType::BIT_OFFSET_BIT,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::NONE
                })
            },

            0xCF => {
                Ok(Instruction {
                    id: 0xCF,
                    mnemonic: "bset",
                    encoding: EncodingType::q_QQ,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_OR,
                    esil: "",
                    src_param: InstructionParameter::BitOffset0,
                    src_type: InstructionParameterType::BIT_OFFSET | InstructionParameterType::BIT_OFFSET_BIT,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::NONE
                })
            },

            0xDF => {
                Ok(Instruction {
                    id: 0xDF,
                    mnemonic: "bset",
                    encoding: EncodingType::q_QQ,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_OR,
                    esil: "",
                    src_param: InstructionParameter::BitOffset0,
                    src_type: InstructionParameterType::BIT_OFFSET | InstructionParameterType::BIT_OFFSET_BIT,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::NONE
                })
            },

            0xEF => {
                Ok(Instruction {
                    id: 0xEF,
                    mnemonic: "bset",
                    encoding: EncodingType::q_QQ,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_OR,
                    esil: "",
                    src_param: InstructionParameter::BitOffset0,
                    src_type: InstructionParameterType::BIT_OFFSET | InstructionParameterType::BIT_OFFSET_BIT,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::NONE
                })
            },

            0xFF => {
                Ok(Instruction {
                    id: 0xFF,
                    mnemonic: "bset",
                    encoding: EncodingType::q_QQ,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_OR,
                    esil: "",
                    src_param: InstructionParameter::BitOffset0,
                    src_type: InstructionParameterType::BIT_OFFSET | InstructionParameterType::BIT_OFFSET_BIT,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::NONE
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
                    id: 0x7A,
                    mnemonic: "bxor",
                    encoding: EncodingType::QQ_ZZ_qz,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_XOR,
                    esil: "",
                    src_param: InstructionParameter::BitOffset1,
                    src_type: InstructionParameterType::BIT_OFFSET | InstructionParameterType::BIT_OFFSET_BIT,
                    dst_param: InstructionParameter::BitOffset0,
                    dst_type: InstructionParameterType::BIT_OFFSET | InstructionParameterType::BIT_OFFSET_BIT
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
                    id: 0xCA,
                    mnemonic: "calla",
                    encoding: EncodingType::c0_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CALL,
                    esil: "",
                    src_param: InstructionParameter::Memory,
                    src_type: InstructionParameterType::DIRECT_MEMORY,
                    dst_param: InstructionParameter::Condition,
                    dst_type: InstructionParameterType::CONDITION
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
                    id: 0xAB,
                    mnemonic: "calli",
                    encoding: EncodingType::cn,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CALL | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Register0,
                    src_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER | InstructionParameterType::INDIRECT,
                    dst_param: InstructionParameter::Condition,
                    dst_type: InstructionParameterType::CONDITION
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
                    id: 0xBB,
                    mnemonic: "callr",
                    encoding: EncodingType::rr,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CALL,
                    esil: "",
                    src_param: InstructionParameter::RelativeAddress,
                    src_type: InstructionParameterType::DIRECT_MEMORY,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::NONE
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
                    id: 0xDA,
                    mnemonic: "calls",
                    encoding: EncodingType::SS_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CALL,
                    esil: "",
                    src_param: InstructionParameter::Memory,
                    src_type: InstructionParameterType::DIRECT_MEMORY,
                    dst_param: InstructionParameter::Segment,
                    dst_type: InstructionParameterType::SEGMENT
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
                    id: 0x40,
                    mnemonic: "cmp",
                    encoding: EncodingType::nm,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CMP | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Register1,
                    src_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER
                })
            },

            0x48 => {
                Ok(Instruction {
                    id: 0x48,
                    mnemonic: "cmp",
                    encoding: EncodingType::data3_or_reg,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CMP,
                    esil: "",
                    src_param: InstructionParameter::None,
                    src_type: InstructionParameterType::DATA_3 | InstructionParameterType::WORD_REGISTER,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::NONE
                })
            },

            0x46 => {
                Ok(Instruction {
                    id: 0x46,
                    mnemonic: "cmp",
                    encoding: EncodingType::RR_II_II,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CMP | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Data,
                    src_type: InstructionParameterType::IMMEDIATE | InstructionParameterType::DATA_16,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::SPECIAL_REGISTER | InstructionParameterType::WORD_REGISTER
                })
            },

            0x42 => {
                Ok(Instruction {
                    id: 0x42,
                    mnemonic: "cmp",
                    encoding: EncodingType::RR_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CMP | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Memory,
                    src_type: InstructionParameterType::DIRECT_MEMORY,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::SPECIAL_REGISTER | InstructionParameterType::WORD_REGISTER
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
                    id: 0x41,
                    mnemonic: "cmpb",
                    encoding: EncodingType::nm,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CMP | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Register1,
                    src_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::BYTE_REGISTER,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::BYTE_REGISTER
                })
            },

            0x49 => {
                Ok(Instruction {
                    id: 0x49,
                    mnemonic: "cmpb",
                    encoding: EncodingType::data3_or_reg,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CMP,
                    esil: "",
                    src_param: InstructionParameter::None,
                    src_type: InstructionParameterType::DATA_3 | InstructionParameterType::BYTE_REGISTER,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::NONE
                })
            },

            0x47 => {
                Ok(Instruction {
                    id: 0x47,
                    mnemonic: "cmpb",
                    encoding: EncodingType::RR_II_xx,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CMP | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Data,
                    src_type: InstructionParameterType::IMMEDIATE | InstructionParameterType::DATA_8,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::SPECIAL_REGISTER | InstructionParameterType::BYTE_REGISTER
                })
            },

            0x43 => {
                Ok(Instruction {
                    id: 0x43,
                    mnemonic: "cmpb",
                    encoding: EncodingType::RR_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CMP | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Memory,
                    src_type: InstructionParameterType::DIRECT_MEMORY,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::SPECIAL_REGISTER | InstructionParameterType::BYTE_REGISTER
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
                    id: 0xA0,
                    mnemonic: "cmpd1",
                    encoding: EncodingType::In,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CMP | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Data,
                    src_type: InstructionParameterType::IMMEDIATE | InstructionParameterType::DATA_4,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER
                })
            },

            0xA6 => {
                Ok(Instruction {
                    id: 0xA6,
                    mnemonic: "cmpd1",
                    encoding: EncodingType::Fn_II_II,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CMP | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Data,
                    src_type: InstructionParameterType::IMMEDIATE | InstructionParameterType::DATA_16,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER
                })
            },

            0xA2 => {
                Ok(Instruction {
                    id: 0xA2,
                    mnemonic: "cmpd1",
                    encoding: EncodingType::Fn_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CMP | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Memory,
                    src_type: InstructionParameterType::DIRECT_MEMORY,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER
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
                    id: 0xB0,
                    mnemonic: "cmpd2",
                    encoding: EncodingType::In,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CMP | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Data,
                    src_type: InstructionParameterType::IMMEDIATE | InstructionParameterType::DATA_4,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER
                })
            },

            0xB6 => {
                Ok(Instruction {
                    id: 0xB6,
                    mnemonic: "cmpd2",
                    encoding: EncodingType::Fn_II_II,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CMP | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Data,
                    src_type: InstructionParameterType::IMMEDIATE | InstructionParameterType::DATA_16,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER
                })
            },

            0xB2 => {
                Ok(Instruction {
                    id: 0xB2,
                    mnemonic: "cmpd2",
                    encoding: EncodingType::Fn_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CMP | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Memory,
                    src_type: InstructionParameterType::DIRECT_MEMORY,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER
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
                    id: 0x80,
                    mnemonic: "cmpi1",
                    encoding: EncodingType::In,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CMP | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Data,
                    src_type: InstructionParameterType::IMMEDIATE | InstructionParameterType::DATA_4,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER
                })
            },

            0x86 => {
                Ok(Instruction {
                    id: 0x86,
                    mnemonic: "cmpi1",
                    encoding: EncodingType::Fn_II_II,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CMP | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Data,
                    src_type: InstructionParameterType::IMMEDIATE | InstructionParameterType::DATA_16,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER
                })
            },

            0x82 => {
                Ok(Instruction {
                    id: 0x82,
                    mnemonic: "cmpi1",
                    encoding: EncodingType::Fn_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CMP | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Memory,
                    src_type: InstructionParameterType::DIRECT_MEMORY,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER
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
                    id: 0x90,
                    mnemonic: "cmpi2",
                    encoding: EncodingType::In,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CMP | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Data,
                    src_type: InstructionParameterType::IMMEDIATE | InstructionParameterType::DATA_4,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER
                })
            },

            0x96 => {
                Ok(Instruction {
                    id: 0x96,
                    mnemonic: "cmpi2",
                    encoding: EncodingType::Fn_II_II,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CMP | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Data,
                    src_type: InstructionParameterType::IMMEDIATE | InstructionParameterType::DATA_16,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER
                })
            },

            0x92 => {
                Ok(Instruction {
                    id: 0x92,
                    mnemonic: "cmpi2",
                    encoding: EncodingType::Fn_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CMP | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Memory,
                    src_type: InstructionParameterType::DIRECT_MEMORY,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER
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
                    id: 0x91,
                    mnemonic: "cpl",
                    encoding: EncodingType::n0,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CPL | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Register0,
                    src_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::NONE
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
                    id: 0xB1,
                    mnemonic: "cplb",
                    encoding: EncodingType::n0,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CPL | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Register0,
                    src_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::BYTE_REGISTER,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::NONE
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
                    id: 0xA5,
                    mnemonic: "diswdt",
                    encoding: EncodingType::NO_ARGS4,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_NULL | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::None,
                    src_type: InstructionParameterType::NONE,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::NONE
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
                    id: 0x4B,
                    mnemonic: "div",
                    encoding: EncodingType::nn,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_DIV | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Register0,
                    src_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::NONE
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
                    id: 0x6B,
                    mnemonic: "divl",
                    encoding: EncodingType::nn,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_DIV | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Register0,
                    src_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::NONE
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
                    id: 0x7B,
                    mnemonic: "divlu",
                    encoding: EncodingType::nn,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_DIV | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Register0,
                    src_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::NONE
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
                    id: 0x5B,
                    mnemonic: "divu",
                    encoding: EncodingType::nn,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_DIV | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Register0,
                    src_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::NONE
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
                    id: 0xB5,
                    mnemonic: "einit",
                    encoding: EncodingType::NO_ARGS4,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_NULL,
                    esil: "",
                    src_param: InstructionParameter::None,
                    src_type: InstructionParameterType::NONE,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::NONE
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
                    id: 0xD7,
                    mnemonic: "ext_d7",
                    encoding: EncodingType::ext_d7,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_NULL,
                    esil: "",
                    src_param: InstructionParameter::IRange,
                    src_type: InstructionParameterType::IMMEDIATE,
                    dst_param: InstructionParameter::PageOrSegment,
                    dst_type: InstructionParameterType::IMMEDIATE
                })
            },

            0xDC => {
                Ok(Instruction {
                    id: 0xDC,
                    mnemonic: "ext_dc",
                    encoding: EncodingType::ext_dc,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_NULL | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::IRange,
                    src_type: InstructionParameterType::IMMEDIATE,
                    dst_param: InstructionParameter::Register1,
                    dst_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER
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
                    id: 0x87,
                    mnemonic: "idle",
                    encoding: EncodingType::NO_ARGS4,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_NULL,
                    esil: "",
                    src_param: InstructionParameter::None,
                    src_type: InstructionParameterType::NONE,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::NONE
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
                    id: 0x8A,
                    mnemonic: "jb",
                    encoding: EncodingType::QQ_rr_q0,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_JMP | _RAnalOpType::R_ANAL_OP_TYPE_COND,
                    esil: "",
                    src_param: InstructionParameter::RelativeAddress,
                    src_type: InstructionParameterType::DIRECT_MEMORY,
                    dst_param: InstructionParameter::BitOffset0,
                    dst_type: InstructionParameterType::BIT_OFFSET | InstructionParameterType::BIT_OFFSET_BIT
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
                    id: 0xAA,
                    mnemonic: "jbc",
                    encoding: EncodingType::QQ_rr_q0,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_JMP | _RAnalOpType::R_ANAL_OP_TYPE_COND,
                    esil: "",
                    src_param: InstructionParameter::RelativeAddress,
                    src_type: InstructionParameterType::DIRECT_MEMORY,
                    dst_param: InstructionParameter::BitOffset0,
                    dst_type: InstructionParameterType::BIT_OFFSET | InstructionParameterType::BIT_OFFSET_BIT
                })
            },

            // JMPA: Absolute Conditional Jump
            // If the condition specified by op1 is met, a branch to the absolute address specified by op2 is taken. If the condition
            // is not met, no action is taken, and the instruction following the JMPA instruction is executed normally.
            // 
            // NOTE: Condition flags not affected

            0xEA => {
                Ok(Instruction {
                    id: 0xEA,
                    mnemonic: "jmpa",
                    encoding: EncodingType::c0_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_JMP | _RAnalOpType::R_ANAL_OP_TYPE_COND,
                    esil: "",
                    src_param: InstructionParameter::Memory,
                    src_type: InstructionParameterType::DIRECT_MEMORY,
                    dst_param: InstructionParameter::Condition,
                    dst_type: InstructionParameterType::CONDITION
                })
            },

            // JMPI: Indirect Conditional Jump
            // If the condition specified by op1 is met, a branch to the absolute address specified by op2 is taken. If the condition
            // is not met, no action is taken, and the instruction following the JMPI instruction is executed normally.
            // 
            // NOTE: Condition flags not affected

            0x9C => {
                Ok(Instruction {
                    id: 0x9C,
                    mnemonic: "jmpi",
                    encoding: EncodingType::cn,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_JMP | _RAnalOpType::R_ANAL_OP_TYPE_COND | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Register0,
                    src_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER | InstructionParameterType::INDIRECT,
                    dst_param: InstructionParameter::Condition,
                    dst_type: InstructionParameterType::CONDITION
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
                    id: 0x0D,
                    mnemonic: "jmpr",
                    encoding: EncodingType::cc_rr,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_JMP,
                    esil: "",
                    src_param: InstructionParameter::RelativeAddress,
                    src_type: InstructionParameterType::DIRECT_MEMORY,
                    dst_param: InstructionParameter::Condition,
                    dst_type: InstructionParameterType::CONDITION
                })
            },

            0x1D => {
                Ok(Instruction {
                    id: 0x1D,
                    mnemonic: "jmpr",
                    encoding: EncodingType::cc_rr,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_JMP | _RAnalOpType::R_ANAL_OP_TYPE_COND,
                    esil: "",
                    src_param: InstructionParameter::RelativeAddress,
                    src_type: InstructionParameterType::DIRECT_MEMORY,
                    dst_param: InstructionParameter::Condition,
                    dst_type: InstructionParameterType::CONDITION
                })
            },

            0x2D => {
                Ok(Instruction {
                    id: 0x2D,
                    mnemonic: "jmpr",
                    encoding: EncodingType::cc_rr,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_JMP | _RAnalOpType::R_ANAL_OP_TYPE_COND,
                    esil: "",
                    src_param: InstructionParameter::RelativeAddress,
                    src_type: InstructionParameterType::DIRECT_MEMORY,
                    dst_param: InstructionParameter::Condition,
                    dst_type: InstructionParameterType::CONDITION
                })
            },

            0x3D => {
                Ok(Instruction {
                    id: 0x3D,
                    mnemonic: "jmpr",
                    encoding: EncodingType::cc_rr,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_JMP | _RAnalOpType::R_ANAL_OP_TYPE_COND,
                    esil: "",
                    src_param: InstructionParameter::RelativeAddress,
                    src_type: InstructionParameterType::DIRECT_MEMORY,
                    dst_param: InstructionParameter::Condition,
                    dst_type: InstructionParameterType::CONDITION
                })
            },

            0x4D => {
                Ok(Instruction {
                    id: 0x4D,
                    mnemonic: "jmpr",
                    encoding: EncodingType::cc_rr,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_JMP | _RAnalOpType::R_ANAL_OP_TYPE_COND,
                    esil: "",
                    src_param: InstructionParameter::RelativeAddress,
                    src_type: InstructionParameterType::DIRECT_MEMORY,
                    dst_param: InstructionParameter::Condition,
                    dst_type: InstructionParameterType::CONDITION
                })
            },

            0x5D => {
                Ok(Instruction {
                    id: 0x5D,
                    mnemonic: "jmpr",
                    encoding: EncodingType::cc_rr,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_JMP | _RAnalOpType::R_ANAL_OP_TYPE_COND,
                    esil: "",
                    src_param: InstructionParameter::RelativeAddress,
                    src_type: InstructionParameterType::DIRECT_MEMORY,
                    dst_param: InstructionParameter::Condition,
                    dst_type: InstructionParameterType::CONDITION
                })
            },

            0x6D => {
                Ok(Instruction {
                    id: 0x6D,
                    mnemonic: "jmpr",
                    encoding: EncodingType::cc_rr,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_JMP | _RAnalOpType::R_ANAL_OP_TYPE_COND,
                    esil: "",
                    src_param: InstructionParameter::RelativeAddress,
                    src_type: InstructionParameterType::DIRECT_MEMORY,
                    dst_param: InstructionParameter::Condition,
                    dst_type: InstructionParameterType::CONDITION
                })
            },

            0x7D => {
                Ok(Instruction {
                    id: 0x7D,
                    mnemonic: "jmpr",
                    encoding: EncodingType::cc_rr,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_JMP | _RAnalOpType::R_ANAL_OP_TYPE_COND,
                    esil: "",
                    src_param: InstructionParameter::RelativeAddress,
                    src_type: InstructionParameterType::DIRECT_MEMORY,
                    dst_param: InstructionParameter::Condition,
                    dst_type: InstructionParameterType::CONDITION
                })
            },

            0x8D => {
                Ok(Instruction {
                    id: 0x8D,
                    mnemonic: "jmpr",
                    encoding: EncodingType::cc_rr,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_JMP | _RAnalOpType::R_ANAL_OP_TYPE_COND,
                    esil: "",
                    src_param: InstructionParameter::RelativeAddress,
                    src_type: InstructionParameterType::DIRECT_MEMORY,
                    dst_param: InstructionParameter::Condition,
                    dst_type: InstructionParameterType::CONDITION
                })
            },

            0x9D => {
                Ok(Instruction {
                    id: 0x9D,
                    mnemonic: "jmpr",
                    encoding: EncodingType::cc_rr,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_JMP | _RAnalOpType::R_ANAL_OP_TYPE_COND,
                    esil: "",
                    src_param: InstructionParameter::RelativeAddress,
                    src_type: InstructionParameterType::DIRECT_MEMORY,
                    dst_param: InstructionParameter::Condition,
                    dst_type: InstructionParameterType::CONDITION
                })
            },

            0xAD => {
                Ok(Instruction {
                    id: 0xAD,
                    mnemonic: "jmpr",
                    encoding: EncodingType::cc_rr,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_JMP | _RAnalOpType::R_ANAL_OP_TYPE_COND,
                    esil: "",
                    src_param: InstructionParameter::RelativeAddress,
                    src_type: InstructionParameterType::DIRECT_MEMORY,
                    dst_param: InstructionParameter::Condition,
                    dst_type: InstructionParameterType::CONDITION
                })
            },

            0xBD => {
                Ok(Instruction {
                    id: 0xBD,
                    mnemonic: "jmpr",
                    encoding: EncodingType::cc_rr,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_JMP | _RAnalOpType::R_ANAL_OP_TYPE_COND,
                    esil: "",
                    src_param: InstructionParameter::RelativeAddress,
                    src_type: InstructionParameterType::DIRECT_MEMORY,
                    dst_param: InstructionParameter::Condition,
                    dst_type: InstructionParameterType::CONDITION
                })
            },

            0xCD => {
                Ok(Instruction {
                    id: 0xCD,
                    mnemonic: "jmpr",
                    encoding: EncodingType::cc_rr,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_JMP | _RAnalOpType::R_ANAL_OP_TYPE_COND,
                    esil: "",
                    src_param: InstructionParameter::RelativeAddress,
                    src_type: InstructionParameterType::DIRECT_MEMORY,
                    dst_param: InstructionParameter::Condition,
                    dst_type: InstructionParameterType::CONDITION
                })
            },

            0xDD => {
                Ok(Instruction {
                    id: 0xDD,
                    mnemonic: "jmpr",
                    encoding: EncodingType::cc_rr,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_JMP | _RAnalOpType::R_ANAL_OP_TYPE_COND,
                    esil: "",
                    src_param: InstructionParameter::RelativeAddress,
                    src_type: InstructionParameterType::DIRECT_MEMORY,
                    dst_param: InstructionParameter::Condition,
                    dst_type: InstructionParameterType::CONDITION
                })
            },

            0xED => {
                Ok(Instruction {
                    id: 0xED,
                    mnemonic: "jmpr",
                    encoding: EncodingType::cc_rr,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_JMP | _RAnalOpType::R_ANAL_OP_TYPE_COND,
                    esil: "",
                    src_param: InstructionParameter::RelativeAddress,
                    src_type: InstructionParameterType::DIRECT_MEMORY,
                    dst_param: InstructionParameter::Condition,
                    dst_type: InstructionParameterType::CONDITION
                })
            },

            0xFD => {
                Ok(Instruction {
                    id: 0xFD,
                    mnemonic: "jmpr",
                    encoding: EncodingType::cc_rr,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_JMP | _RAnalOpType::R_ANAL_OP_TYPE_COND,
                    esil: "",
                    src_param: InstructionParameter::RelativeAddress,
                    src_type: InstructionParameterType::DIRECT_MEMORY,
                    dst_param: InstructionParameter::Condition,
                    dst_type: InstructionParameterType::CONDITION
                })
            },

            // JMPS: Absolute Inter-Segment Jump
            // Branches unconditionally to the absolute address specified by op2 within the segment specified by op1.
            // 
            // NOTE: Condition flags not affected

            0xFA => {
                Ok(Instruction {
                    id: 0xFA,
                    mnemonic: "jmps",
                    encoding: EncodingType::SS_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_JMP,
                    esil: "",
                    src_param: InstructionParameter::Memory,
                    src_type: InstructionParameterType::DIRECT_MEMORY,
                    dst_param: InstructionParameter::Segment,
                    dst_type: InstructionParameterType::SEGMENT
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
                    id: 0x9A,
                    mnemonic: "jnb",
                    encoding: EncodingType::QQ_rr_q0,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_JMP | _RAnalOpType::R_ANAL_OP_TYPE_COND,
                    esil: "",
                    src_param: InstructionParameter::RelativeAddress,
                    src_type: InstructionParameterType::DIRECT_MEMORY,
                    dst_param: InstructionParameter::BitOffset0,
                    dst_type: InstructionParameterType::BIT_OFFSET | InstructionParameterType::BIT_OFFSET_BIT
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
                    id: 0xBA,
                    mnemonic: "jnbs",
                    encoding: EncodingType::QQ_rr_q0,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_JMP | _RAnalOpType::R_ANAL_OP_TYPE_COND,
                    esil: "",
                    src_param: InstructionParameter::RelativeAddress,
                    src_type: InstructionParameterType::DIRECT_MEMORY,
                    dst_param: InstructionParameter::BitOffset0,
                    dst_type: InstructionParameterType::BIT_OFFSET | InstructionParameterType::BIT_OFFSET_BIT
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
                    id: 0xF0,
                    mnemonic: "mov",
                    encoding: EncodingType::nm,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "{reg1},NUM,{reg0},=",
                    src_param: InstructionParameter::Register1,
                    src_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER
                })
            },

            0xE0 => {
                Ok(Instruction {
                    id: 0xE0,
                    mnemonic: "mov",
                    encoding: EncodingType::In,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "{immed},{reg0},=",
                    src_param: InstructionParameter::Data,
                    src_type: InstructionParameterType::IMMEDIATE | InstructionParameterType::DATA_4,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER
                })
            },

            0xE6 => {
                Ok(Instruction {
                    id: 0xE6,
                    mnemonic: "mov",
                    encoding: EncodingType::RR_II_II,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "{immed},{reg0},=",
                    src_param: InstructionParameter::Data,
                    src_type: InstructionParameterType::IMMEDIATE | InstructionParameterType::DATA_16,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::SPECIAL_REGISTER | InstructionParameterType::WORD_REGISTER
                })
            },

            0xA8 => {
                Ok(Instruction {
                    id: 0xA8,
                    mnemonic: "mov",
                    encoding: EncodingType::nm,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Register1,
                    src_type: InstructionParameterType::INDIRECT | InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER
                })
            },

            0x98 => {
                Ok(Instruction {
                    id: 0x98,
                    mnemonic: "mov",
                    encoding: EncodingType::nm,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Register1,
                    src_type: InstructionParameterType::INDIRECT | InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER | InstructionParameterType::INCREMENT,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER
                })
            },

            0xB8 => {
                Ok(Instruction {
                    id: 0xB8,
                    mnemonic: "mov",
                    encoding: EncodingType::nm,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Register0,
                    src_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER,
                    dst_param: InstructionParameter::Register1,
                    dst_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER | InstructionParameterType::INDIRECT
                })
            },

            0x88 => {
                Ok(Instruction {
                    id: 0x88,
                    mnemonic: "mov",
                    encoding: EncodingType::nm,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Register0,
                    src_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER,
                    dst_param: InstructionParameter::Register1,
                    dst_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER | InstructionParameterType::INDIRECT | InstructionParameterType::DECREMENT
                })
            },

            0xC8 => {
                Ok(Instruction {
                    id: 0xC8,
                    mnemonic: "mov",
                    encoding: EncodingType::nm,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Register1,
                    src_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER | InstructionParameterType::INDIRECT,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER | InstructionParameterType::INDIRECT
                })
            },

            0xD8 => {
                Ok(Instruction {
                    id: 0xD8,
                    mnemonic: "mov",
                    encoding: EncodingType::nm,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Register1,
                    src_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER | InstructionParameterType::INDIRECT,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER | InstructionParameterType::INDIRECT | InstructionParameterType::INCREMENT
                })
            },

            0xE8 => {
                Ok(Instruction {
                    id: 0xE8,
                    mnemonic: "mov",
                    encoding: EncodingType::nm,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Register1,
                    src_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType:: WORD_REGISTER | InstructionParameterType::INDIRECT | InstructionParameterType::INCREMENT,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER | InstructionParameterType::INDIRECT
                })
            },

            0xD4 => {
                Ok(Instruction {
                    id: 0xD4,
                    mnemonic: "mov",
                    encoding: EncodingType::nm_II_II,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "{reg1},NUM,{immed},+,[],{reg0}",
                    src_param: InstructionParameter::Register1,
                    src_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER | InstructionParameterType::INDIRECT | InstructionParameterType::IMMEDIATE | InstructionParameterType::INCREMENT | InstructionParameterType::DATA_16,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER
                })
            },

            0xC4 => {
                Ok(Instruction {
                    id: 0xC4,
                    mnemonic: "mov",
                    encoding: EncodingType::nm_II_II,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "{reg0},{reg1},NUM,{immed},+,=[]",
                    src_param: InstructionParameter::Register0,
                    src_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER,
                    dst_param: InstructionParameter::Register1,
                    dst_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER | InstructionParameterType::INDIRECT | InstructionParameterType::INCREMENT | InstructionParameterType::IMMEDIATE | InstructionParameterType::DATA_16
                })
            },

            0x84 => {
                Ok(Instruction {
                    id: 0x84,
                    mnemonic: "mov",
                    encoding: EncodingType::_0n_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Memory,
                    src_type: InstructionParameterType::DIRECT_MEMORY,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER | InstructionParameterType::INDIRECT
                })
            },

            0x94 => {
                Ok(Instruction {
                    id: 0x94,
                    mnemonic: "mov",
                    encoding: EncodingType::_0n_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Register0,
                    src_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER | InstructionParameterType::INDIRECT,
                    dst_param: InstructionParameter::Memory,
                    dst_type: InstructionParameterType::DIRECT_MEMORY
                })
            },

            0xF2 => {
                Ok(Instruction {
                    id: 0xF2,
                    mnemonic: "mov",
                    encoding: EncodingType::RR_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Memory,
                    src_type: InstructionParameterType::DIRECT_MEMORY,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::SPECIAL_REGISTER | InstructionParameterType::WORD_REGISTER
                })
            },

            0xF6 => {
                Ok(Instruction {
                    id: 0xF6,
                    mnemonic: "mov",
                    encoding: EncodingType::RR_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Register0,
                    src_type: InstructionParameterType::SPECIAL_REGISTER | InstructionParameterType::WORD_REGISTER,
                    dst_param: InstructionParameter::Memory,
                    dst_type: InstructionParameterType::DIRECT_MEMORY
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
                    encoding: EncodingType::nm,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Register1,
                    src_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::BYTE_REGISTER,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::BYTE_REGISTER
                })
            },

            0xE1 => {
                Ok(Instruction {
                    // Rbn, #data4
                    // Move immediate byte data to direct GPR
                    id: 0xE1,
                    mnemonic: "movb",
                    encoding: EncodingType::In,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Data,
                    src_type: InstructionParameterType::IMMEDIATE | InstructionParameterType::DATA_4,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::BYTE_REGISTER
                })
            },

            0xE7 => {
                Ok(Instruction {
                    // reg, #data8
                    // Move immediate byte data to direct register
                    id: 0xE7,
                    mnemonic: "movb",
                    encoding: EncodingType::RR_II_xx,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "{immed},{reg0},=",
                    src_param: InstructionParameter::Data,
                    src_type: InstructionParameterType::IMMEDIATE | InstructionParameterType::DATA_8,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::SPECIAL_REGISTER | InstructionParameterType::BYTE_REGISTER
                })
            },

            0xA9 => {
                Ok(Instruction {
                    // Rbn, [Rwm]
                    // Move indirect byte memory to direct GPR
                    id: 0xA9,
                    mnemonic: "movb",
                    encoding: EncodingType::nm,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Register1,
                    src_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER | InstructionParameterType::INDIRECT,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::BYTE_REGISTER
                })
            },

            0x99 => {
                Ok(Instruction {
                    // Rbn, [Rwm+]
                    // Move indirect byte memory to direct GPR and post-increment source pointer by 1
                    id: 0x99,
                    mnemonic: "movb",
                    encoding: EncodingType::nm,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Register1,
                    src_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER | InstructionParameterType::INDIRECT | InstructionParameterType::INCREMENT,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::BYTE_REGISTER
                })
            },

            0xB9 => {
                Ok(Instruction {
                    // [Rwm], Rbn
                    // Move direct byte GPR to indirect memory
                    id: 0xB9,
                    mnemonic: "movb",
                    encoding: EncodingType::nm,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Register0,
                    src_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::BYTE_REGISTER,
                    dst_param: InstructionParameter::Register1,
                    dst_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER | InstructionParameterType::INDIRECT
                })
            },

            0x89 => {
                Ok(Instruction {
                    // [-Rwm], Rbn
                    // Pre-decrement destination pointer by 1 and move direct byte GPR to indirect memory
                    id: 0x89,
                    mnemonic: "movb",
                    encoding: EncodingType::nm,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Register0,
                    src_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::BYTE_REGISTER,
                    dst_param: InstructionParameter::Register1,
                    dst_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER | InstructionParameterType::INDIRECT | InstructionParameterType::DECREMENT
                })
            },

            0xC9 => {
                Ok(Instruction {
                    // [Rwn], [Rwm]
                    // Move indirect byte memory to indirect memory
                    id: 0xC9,
                    mnemonic: "movb",
                    encoding: EncodingType::nm,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Register1,
                    src_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER | InstructionParameterType::INDIRECT,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER | InstructionParameterType::INDIRECT
                })
            },

            0xD9 => {
                Ok(Instruction {
                    // [Rwn+], [Rwm]
                    // Move indirect byte memory to indirect memory and post-increment destination pointer by 1
                    id: 0xD9,
                    mnemonic: "movb",
                    encoding: EncodingType::nm,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Register1,
                    src_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER | InstructionParameterType::INDIRECT,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER | InstructionParameterType::INDIRECT | InstructionParameterType::INCREMENT
                })
            },

            0xE9 => {
                Ok(Instruction {
                    // [Rwn], [Rwm+]
                    // Move indirect byte memory to indirect memory and post-increment source pointer by 1
                    id: 0xE9,
                    mnemonic: "movb",
                    encoding: EncodingType::nm,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Register1,
                    src_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER | InstructionParameterType::INDIRECT | InstructionParameterType::INCREMENT,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER | InstructionParameterType::INDIRECT
                })
            },

            0xF4 => {
                Ok(Instruction {
                    // Rbn, [Rwm+#data16]
                    // Move indirect byte memory by base plus constant to direct byte GPR
                    id: 0xF4,
                    mnemonic: "movb",
                    encoding: EncodingType::nm_II_II,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Register1,
                    src_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER | InstructionParameterType::INDIRECT | InstructionParameterType::INCREMENT | InstructionParameterType::IMMEDIATE | InstructionParameterType::DATA_16,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::BYTE_REGISTER
                })
            },

            0xE4 => {
                Ok(Instruction {
                    // [Rwm+#data16], Rbn
                    // Move direct byte GPR to indirect memory by base plus constant
                    id: 0xE4,
                    mnemonic: "movb",
                    encoding: EncodingType::nm_II_II,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "{reg0},{reg1},NUM,{immed},+,=[]",
                    src_param: InstructionParameter::Register0,
                    src_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType:: BYTE_REGISTER,
                    dst_param: InstructionParameter::Register1,
                    dst_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER | InstructionParameterType::INDIRECT | InstructionParameterType::INCREMENT | InstructionParameterType::IMMEDIATE | InstructionParameterType::DATA_16
                })
            },

            0xA4 => {
                Ok(Instruction {
                    // [Rwn], mem
                    // Move direct byte memory to indirect memory
                    id: 0xA4,
                    mnemonic: "movb",
                    encoding: EncodingType::_0n_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Memory,
                    src_type: InstructionParameterType::DIRECT_MEMORY,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER | InstructionParameterType::INDIRECT
                })
            },

            0xB4 => {
                Ok(Instruction {
                    // mem, [Rwn]
                    // Move indirect byte memory to direct memory
                    id: 0xB4,
                    mnemonic: "movb",
                    encoding: EncodingType::_0n_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Register0,
                    src_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER | InstructionParameterType::INDIRECT,
                    dst_param: InstructionParameter::Memory,
                    dst_type: InstructionParameterType::DIRECT_MEMORY
                })
            },

            0xF3 => {
                Ok(Instruction {
                    // reg, mem
                    // Move direct byte memory to direct register
                    id: 0xF3,
                    mnemonic: "movb",
                    encoding: EncodingType::RR_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Memory,
                    src_type: InstructionParameterType::DIRECT_MEMORY,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::SPECIAL_REGISTER | InstructionParameterType::BYTE_REGISTER
                })
            },

            0xF7 => {
                Ok(Instruction {
                    // mem, reg
                    // Move direct byte register to direct memory
                    id: 0xF7,
                    mnemonic: "movb",
                    encoding: EncodingType::RR_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Register0,
                    src_type: InstructionParameterType::SPECIAL_REGISTER | InstructionParameterType::BYTE_REGISTER,
                    dst_param: InstructionParameter::Memory,
                    dst_type: InstructionParameterType::DIRECT_MEMORY
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
                    // Rwn, Rbm
                    // Move direct byte GPR with sign extension to direct word GPR
                    id: 0xD0,
                    mnemonic: "movbs",
                    encoding: EncodingType::mn,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Register1,
                    src_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::BYTE_REGISTER,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER
                })
            },

            0xD2 => {
                Ok(Instruction {
                    // reg, mem
                    // Move direct byte memory with sign extension to direct word register
                    id: 0xD2,
                    mnemonic: "movbs",
                    encoding: EncodingType::RR_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Memory,
                    src_type: InstructionParameterType::DIRECT_MEMORY,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::SPECIAL_REGISTER | InstructionParameterType::BYTE_REGISTER
                })
            },

            0xD5 => {
                Ok(Instruction {
                    // mem, reg
                    // Move direct byte register with sign extension to direct word memory
                    id: 0xD5,
                    mnemonic: "movbs",
                    encoding: EncodingType::RR_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Register0,
                    src_type: InstructionParameterType::SPECIAL_REGISTER | InstructionParameterType::BYTE_REGISTER,
                    dst_param: InstructionParameter::Memory,
                    dst_type: InstructionParameterType::DIRECT_MEMORY
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
                    // Rwn, Rbm
                    // Move direct byte GPR with zero extension to direct word GPR
                    id: 0xC0,
                    mnemonic: "movbz",
                    encoding: EncodingType::mn,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Register1,
                    src_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::BYTE_REGISTER,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER
                })
            },

            0xC2 => {
                Ok(Instruction {
                    // reg, mem
                    // Move direct byte memory with zero extension to direct word register
                    id: 0xC2,
                    mnemonic: "movbz",
                    encoding: EncodingType::RR_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Memory,
                    src_type: InstructionParameterType::DIRECT_MEMORY,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::SPECIAL_REGISTER | InstructionParameterType::BYTE_REGISTER
                })
            },

            0xC5 => {
                Ok(Instruction {
                    // mem, reg
                    // Move direct byte register with zero extension to direct word memory
                    id: 0xC5,
                    mnemonic: "movbz",
                    encoding: EncodingType::RR_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Register0,
                    src_type: InstructionParameterType::SPECIAL_REGISTER | InstructionParameterType::BYTE_REGISTER,
                    dst_param: InstructionParameter::Memory,
                    dst_type: InstructionParameterType::DIRECT_MEMORY
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
                    encoding: EncodingType::nm,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MUL | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Register1,
                    src_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER
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
                    encoding: EncodingType::nm,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MUL | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Register1,
                    src_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER
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
                    id: 0x81,
                    mnemonic: "neg",
                    encoding: EncodingType::n0,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CPL | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Register0,
                    src_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::NONE
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
                    id: 0xA1,
                    mnemonic: "negb",
                    encoding: EncodingType::n0,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CPL | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Register0,
                    src_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::BYTE_REGISTER,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::NONE
                })
            },

            // NOP: No Operation
            // This instruction causes a null operation to be performed. A null operation causes no change in the status
            // of the flags.

            0xCC => {
                Ok(Instruction {
                    id: 0xCC,
                    mnemonic: "nop",
                    encoding: EncodingType::NO_ARGS2,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_NOP,
                    esil: "",
                    src_param: InstructionParameter::None,
                    src_type: InstructionParameterType::NONE,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::NONE
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
                    id: 0x70,
                    mnemonic: "or",
                    encoding: EncodingType::nm,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_OR | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "{reg1},NUM,{reg0},|",
                    src_param: InstructionParameter::Register1,
                    src_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER
                })
            },

            0x78 => {
                Ok(Instruction {
                    id: 0x78,
                    mnemonic: "or",
                    encoding: EncodingType::data3_or_reg,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_OR,
                    esil: "",
                    src_param: InstructionParameter::None,
                    src_type: InstructionParameterType::DATA_3 | InstructionParameterType::WORD_REGISTER,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::NONE
                })
            },

            0x76 => {
                Ok(Instruction {
                    id: 0x76,
                    mnemonic: "or",
                    encoding: EncodingType::RR_II_II,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_OR | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Data,
                    src_type: InstructionParameterType::IMMEDIATE | InstructionParameterType::DATA_16,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::SPECIAL_REGISTER | InstructionParameterType::WORD_REGISTER
                })
            },

            0x72 => {
                Ok(Instruction {
                    id: 0x72,
                    mnemonic: "or",
                    encoding: EncodingType::RR_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_OR | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Memory,
                    src_type: InstructionParameterType::DIRECT_MEMORY,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::SPECIAL_REGISTER | InstructionParameterType::WORD_REGISTER
                })
            },

            0x74 => {
                Ok(Instruction {
                    id: 0x74,
                    mnemonic: "or",
                    encoding: EncodingType::RR_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_OR | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Register0,
                    src_type: InstructionParameterType::SPECIAL_REGISTER | InstructionParameterType::WORD_REGISTER,
                    dst_param: InstructionParameter::Memory,
                    dst_type: InstructionParameterType::DIRECT_MEMORY
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
                    id: 0x71,
                    mnemonic: "orb",
                    encoding: EncodingType::nm,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_OR | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Register1,
                    src_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::BYTE_REGISTER,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::BYTE_REGISTER
                })
            },

            0x79 => {
                Ok(Instruction {
                    id: 0x79,
                    mnemonic: "orb",
                    encoding: EncodingType::data3_or_reg,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_OR,
                    esil: "",
                    src_param: InstructionParameter::None,
                    src_type: InstructionParameterType::DATA_3 | InstructionParameterType::BYTE_REGISTER,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::NONE
                })
            },

            0x77 => {
                Ok(Instruction {
                    id: 0x77,
                    mnemonic: "orb",
                    encoding: EncodingType::RR_II_xx,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_OR | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Data,
                    src_type: InstructionParameterType::IMMEDIATE | InstructionParameterType::DATA_8,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::SPECIAL_REGISTER | InstructionParameterType::BYTE_REGISTER
                })
            },

            0x73 => {
                Ok(Instruction {
                    id: 0x73,
                    mnemonic: "orb",
                    encoding: EncodingType::RR_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_OR | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Memory,
                    src_type: InstructionParameterType::DIRECT_MEMORY,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::SPECIAL_REGISTER | InstructionParameterType::BYTE_REGISTER
                })
            },

            0x75 => {
                Ok(Instruction {
                    id: 0x75,
                    mnemonic: "orb",
                    encoding: EncodingType::RR_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_OR | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Register0,
                    src_type: InstructionParameterType::SPECIAL_REGISTER | InstructionParameterType::BYTE_REGISTER,
                    dst_param: InstructionParameter::Memory,
                    dst_type: InstructionParameterType::DIRECT_MEMORY
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
                    id: 0xE2,
                    mnemonic: "pcall",
                    encoding: EncodingType::RR_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CALL | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Memory,
                    src_type: InstructionParameterType::DIRECT_MEMORY,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::SPECIAL_REGISTER | InstructionParameterType::WORD_REGISTER
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
                    id: 0xFC,
                    mnemonic: "pop",
                    encoding: EncodingType::RR,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_POP | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Register0,
                    src_type: InstructionParameterType::SPECIAL_REGISTER | InstructionParameterType::WORD_REGISTER,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::NONE
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
                    id: 0x2B,
                    mnemonic: "prior",
                    encoding: EncodingType::nm,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_NULL | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Register1,
                    src_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER
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
                    id: 0xEC,
                    mnemonic: "push",
                    encoding: EncodingType::RR,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_PUSH | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Register0,
                    src_type: InstructionParameterType::SPECIAL_REGISTER | InstructionParameterType::WORD_REGISTER,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::NONE
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
                    id: 0x97,
                    mnemonic: "pwrdn",
                    encoding: EncodingType::NO_ARGS4,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_NULL,
                    esil: "",
                    src_param: InstructionParameter::None,
                    src_type: InstructionParameterType::NONE,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::NONE
                })
            },

            // RET: Return from Subroutine
            // Returns from a subroutine. The IP is popped from the system stack. Execution resumes at the instruction following
            // the CALL instruction in the calling routine.
            // 
            // NOTE: Condition flags not affected

            0xCB => {
                Ok(Instruction {
                    id: 0xCB,
                    mnemonic: "ret",
                    encoding: EncodingType::NO_ARGS2,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_RET,
                    esil: "",
                    src_param: InstructionParameter::None,
                    src_type: InstructionParameterType::NONE,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::NONE
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
                    id: 0xFB,
                    mnemonic: "reti",
                    encoding: EncodingType::NO_ARGS2,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_RET,
                    esil: "",
                    src_param: InstructionParameter::None,
                    src_type: InstructionParameterType::NONE,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::NONE
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
                    id: 0xEB,
                    mnemonic: "retp",
                    encoding: EncodingType::RR,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_RET | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Register0,
                    src_type: InstructionParameterType::SPECIAL_REGISTER | InstructionParameterType::WORD_REGISTER,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::NONE
                })
            },

            // RETS: Return from Inter-Segment Subroutine
            // Returns from an inter-segment subroutine. The IP and CSP are popped from the system stack. Execution resumes at the
            // instruction following the CALLS instruction in the calling routine.
            // 
            // NOTE: Condition flags not affected

            0xDB => {
                Ok(Instruction {
                    id: 0xDB,
                    mnemonic: "rets",
                    encoding: EncodingType::NO_ARGS2,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_RET,
                    esil: "",
                    src_param: InstructionParameter::None,
                    src_type: InstructionParameterType::NONE,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::NONE
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
                    id: 0x0C,
                    mnemonic: "rol",
                    encoding: EncodingType::nm,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_ROL | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "{reg1},NUM,{reg0},<<<",
                    src_param: InstructionParameter::Register1,
                    src_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER
                })
            },

            0x1C => {
                Ok(Instruction {
                    id: 0x1C,
                    mnemonic: "rol",
                    encoding: EncodingType::In,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_ROL | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "{immed},{reg0},<<<",
                    src_param: InstructionParameter::Data,
                    src_type: InstructionParameterType::IMMEDIATE | InstructionParameterType::DATA_4,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER
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
                    id: 0x2C,
                    mnemonic: "ror",
                    encoding: EncodingType::nm,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_ROR | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "{reg1},NUM,{reg0},>>>",
                    src_param: InstructionParameter::Register1,
                    src_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER
                })
            },

            0x3C => {
                Ok(Instruction {
                    id: 0x3C,
                    mnemonic: "ror",
                    encoding: EncodingType::In,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_ROR | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Data,
                    src_type: InstructionParameterType::IMMEDIATE | InstructionParameterType::DATA_4,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER
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
                    id: 0xC6,
                    mnemonic: "scxt",
                    encoding: EncodingType::RR_II_II,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_NULL | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Data,
                    src_type: InstructionParameterType::IMMEDIATE | InstructionParameterType::DATA_16,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::SPECIAL_REGISTER | InstructionParameterType::WORD_REGISTER
                })
            },

            0xD6 => {
                Ok(Instruction {
                    id: 0xD6,
                    mnemonic: "scxt",
                    encoding: EncodingType::RR_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_NULL | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Memory,
                    src_type: InstructionParameterType::DIRECT_MEMORY,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::SPECIAL_REGISTER | InstructionParameterType::WORD_REGISTER
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
                    id: 0x4C,
                    mnemonic: "shl",
                    encoding: EncodingType::nm,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_SHL | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Register1,
                    src_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER
                })
            },

            0x5C => {
                Ok(Instruction {
                    id: 0x5C,
                    mnemonic: "shl",
                    encoding: EncodingType::In,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_SHL | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Data,
                    src_type: InstructionParameterType::IMMEDIATE | InstructionParameterType::DATA_4,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER
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
                    id: 0x6C,
                    mnemonic: "shr",
                    encoding: EncodingType::nm,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_SHR | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Register1,
                    src_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER
                })
            },

            0x7C => {
                Ok(Instruction {
                    id: 0x7C,
                    mnemonic: "shr",
                    encoding: EncodingType::In,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_SHR | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Data,
                    src_type: InstructionParameterType::IMMEDIATE | InstructionParameterType::DATA_4,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER
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
                    id: 0xB7,
                    mnemonic: "srst",
                    encoding: EncodingType::NO_ARGS4,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_NULL,
                    esil: "",
                    src_param: InstructionParameter::None,
                    src_type: InstructionParameterType::NONE,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::NONE
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
                    id: 0xA7,
                    mnemonic: "srvwdt",
                    encoding: EncodingType::NO_ARGS4,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_NULL,
                    esil: "",
                    src_param: InstructionParameter::None,
                    src_type: InstructionParameterType::NONE,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::NONE
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
                    id: 0x20,
                    mnemonic: "sub",
                    encoding: EncodingType::nm,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_SUB | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Register1,
                    src_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER
                })
            },

            0x28 => {
                Ok(Instruction {
                    id: 0x28,
                    mnemonic: "sub",
                    encoding: EncodingType::data3_or_reg,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_SUB,
                    esil: "",
                    src_param: InstructionParameter::None,
                    src_type: InstructionParameterType::DATA_3 | InstructionParameterType::WORD_REGISTER,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::NONE
                })
            },

            0x26 => {
                Ok(Instruction {
                    id: 0x26,
                    mnemonic: "sub",
                    encoding: EncodingType::RR_II_II,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_SUB | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Data,
                    src_type: InstructionParameterType::IMMEDIATE | InstructionParameterType::DATA_16,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::SPECIAL_REGISTER | InstructionParameterType::WORD_REGISTER
                })
            },

            0x22 => {
                Ok(Instruction {
                    id: 0x22,
                    mnemonic: "sub",
                    encoding: EncodingType::RR_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_SUB | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Memory,
                    src_type: InstructionParameterType::DIRECT_MEMORY,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::SPECIAL_REGISTER | InstructionParameterType::WORD_REGISTER
                })
            },

            0x24 => {
                Ok(Instruction {
                    id: 0x24,
                    mnemonic: "sub",
                    encoding: EncodingType::RR_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_SUB | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Register0,
                    src_type: InstructionParameterType::SPECIAL_REGISTER | InstructionParameterType::WORD_REGISTER,
                    dst_param: InstructionParameter::Memory,
                    dst_type: InstructionParameterType::DIRECT_MEMORY
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
                    id: 0x21,
                    mnemonic: "subb",
                    encoding: EncodingType::nm,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_SUB | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Register1,
                    src_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::BYTE_REGISTER,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::BYTE_REGISTER
                })
            },

            0x29 => {
                Ok(Instruction {
                    id: 0x29,
                    mnemonic: "subb",
                    encoding: EncodingType::data3_or_reg,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_SUB,
                    esil: "",
                    src_param: InstructionParameter::None,
                    src_type: InstructionParameterType::DATA_3 | InstructionParameterType::BYTE_REGISTER,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::NONE
                })
            },

            0x27 => {
                Ok(Instruction {
                    id: 0x27,
                    mnemonic: "subb",
                    encoding: EncodingType::RR_II_xx,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_SUB | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Data,
                    src_type: InstructionParameterType::IMMEDIATE | InstructionParameterType::DATA_8,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::SPECIAL_REGISTER | InstructionParameterType::BYTE_REGISTER
                })
            },

            0x23 => {
                Ok(Instruction {
                    id: 0x23,
                    mnemonic: "subb",
                    encoding: EncodingType::RR_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_SUB | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Memory,
                    src_type: InstructionParameterType::DIRECT_MEMORY,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::SPECIAL_REGISTER | InstructionParameterType::BYTE_REGISTER
                })
            },

            0x25 => {
                Ok(Instruction {
                    id: 0x25,
                    mnemonic: "subb",
                    encoding: EncodingType::RR_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_SUB | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Register0,
                    src_type: InstructionParameterType::SPECIAL_REGISTER | InstructionParameterType::BYTE_REGISTER,
                    dst_param: InstructionParameter::Memory,
                    dst_type: InstructionParameterType::DIRECT_MEMORY
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
                    id: 0x30,
                    mnemonic: "subc",
                    encoding: EncodingType::nm,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_SUB | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Register1,
                    src_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER
                })
            },

            0x38 => {
                Ok(Instruction {
                    id: 0x38,
                    mnemonic: "subc",
                    encoding: EncodingType::data3_or_reg,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_SUB,
                    esil: "",
                    src_param: InstructionParameter::None,
                    src_type: InstructionParameterType::DATA_3 | InstructionParameterType::WORD_REGISTER,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::NONE
                })
            },

            0x36 => {
                Ok(Instruction {
                    id: 0x36,
                    mnemonic: "subc",
                    encoding: EncodingType::RR_II_II,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_SUB | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Data,
                    src_type: InstructionParameterType::IMMEDIATE | InstructionParameterType::DATA_16,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::SPECIAL_REGISTER | InstructionParameterType::WORD_REGISTER
                })
            },

            0x32 => {
                Ok(Instruction {
                    id: 0x32,
                    mnemonic: "subc",
                    encoding: EncodingType::RR_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_SUB | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Memory,
                    src_type: InstructionParameterType::DIRECT_MEMORY,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::SPECIAL_REGISTER | InstructionParameterType::WORD_REGISTER
                })
            },

            0x34 => {
                Ok(Instruction {
                    id: 0x34,
                    mnemonic: "subc",
                    encoding: EncodingType::RR_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_SUB | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Register0,
                    src_type: InstructionParameterType::SPECIAL_REGISTER | InstructionParameterType::WORD_REGISTER,
                    dst_param: InstructionParameter::Memory,
                    dst_type: InstructionParameterType::DIRECT_MEMORY
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
                    id: 0x31,
                    mnemonic: "subcb",
                    encoding: EncodingType::nm,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_SUB | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Register1,
                    src_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::BYTE_REGISTER,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::BYTE_REGISTER
                })
            },

            0x39 => {
                Ok(Instruction {
                    id: 0x39,
                    mnemonic: "subcb",
                    encoding: EncodingType::data3_or_reg,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_SUB,
                    esil: "",
                    src_param: InstructionParameter::None,
                    src_type: InstructionParameterType::DATA_3 | InstructionParameterType::WORD_REGISTER,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::NONE
                })
            },

            0x37 => {
                Ok(Instruction {
                    id: 0x37,
                    mnemonic: "subcb",
                    encoding: EncodingType::RR_II_xx,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_SUB | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Data,
                    src_type: InstructionParameterType::IMMEDIATE | InstructionParameterType::DATA_8,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::SPECIAL_REGISTER | InstructionParameterType::BYTE_REGISTER
                })
            },

            0x33 => {
                Ok(Instruction {
                    id: 0x33,
                    mnemonic: "subcb",
                    encoding: EncodingType::RR_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_SUB | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Memory,
                    src_type: InstructionParameterType::DIRECT_MEMORY,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::SPECIAL_REGISTER | InstructionParameterType::BYTE_REGISTER
                })
            },

            0x35 => {
                Ok(Instruction {
                    id: 0x35,
                    mnemonic: "subcb",
                    encoding: EncodingType::RR_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_SUB | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Register0,
                    src_type: InstructionParameterType::SPECIAL_REGISTER | InstructionParameterType::BYTE_REGISTER,
                    dst_param: InstructionParameter::Memory,
                    dst_type: InstructionParameterType::DIRECT_MEMORY
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
                    id: 0x9B,
                    mnemonic: "trap",
                    encoding: EncodingType::trap7,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_TRAP,
                    esil: "",
                    src_param: InstructionParameter::Trap,
                    src_type: InstructionParameterType::TRAP,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::NONE
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
                    id: 0x50,
                    mnemonic: "xor",
                    encoding: EncodingType::nm,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_XOR | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Register1,
                    src_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::WORD_REGISTER
                })
            },

            0x58 => {
                Ok(Instruction {
                    id: 0x58,
                    mnemonic: "xor",
                    encoding: EncodingType::data3_or_reg,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_XOR,
                    esil: "",
                    src_param: InstructionParameter::None,
                    src_type: InstructionParameterType::DATA_3 | InstructionParameterType::WORD_REGISTER,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::NONE
                })
            },

            0x56 => {
                Ok(Instruction {
                    id: 0x56,
                    mnemonic: "xor",
                    encoding: EncodingType::RR_II_II,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_XOR | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Data,
                    src_type: InstructionParameterType::IMMEDIATE | InstructionParameterType::DATA_16,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::SPECIAL_REGISTER | InstructionParameterType::WORD_REGISTER
                })
            },

            0x52 => {
                Ok(Instruction {
                    id: 0x52,
                    mnemonic: "xor",
                    encoding: EncodingType::RR_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_XOR | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Memory,
                    src_type: InstructionParameterType::DIRECT_MEMORY,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::SPECIAL_REGISTER | InstructionParameterType::WORD_REGISTER
                })
            },

            0x54 => {
                Ok(Instruction {
                    id: 0x54,
                    mnemonic: "xor",
                    encoding: EncodingType::RR_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_XOR | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Register0,
                    src_type: InstructionParameterType::SPECIAL_REGISTER | InstructionParameterType::WORD_REGISTER,
                    dst_param: InstructionParameter::Memory,
                    dst_type: InstructionParameterType::DIRECT_MEMORY
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
                    id: 0x51,
                    mnemonic: "xorb",
                    encoding: EncodingType::nm,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_XOR | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Register1,
                    src_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::BYTE_REGISTER,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::GENERAL_REGISTER | InstructionParameterType::BYTE_REGISTER
                })
            },

            0x59 => {
                Ok(Instruction {
                    id: 0x59,
                    mnemonic: "xorb",
                    encoding: EncodingType::data3_or_reg,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_XOR,
                    esil: "",
                    src_param: InstructionParameter::None,
                    src_type: InstructionParameterType::DATA_3 | InstructionParameterType::BYTE_REGISTER,
                    dst_param: InstructionParameter::None,
                    dst_type: InstructionParameterType::NONE
                })
            },

            0x57 => {
                Ok(Instruction {
                    id: 0x57,
                    mnemonic: "xorb",
                    encoding: EncodingType::RR_II_xx,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_XOR | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Data,
                    src_type: InstructionParameterType::IMMEDIATE | InstructionParameterType::DATA_8,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::SPECIAL_REGISTER | InstructionParameterType::BYTE_REGISTER
                })
            },

            0x53 => {
                Ok(Instruction {
                    id: 0x53,
                    mnemonic: "xorb",
                    encoding: EncodingType::RR_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_XOR | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Memory,
                    src_type: InstructionParameterType::DIRECT_MEMORY,
                    dst_param: InstructionParameter::Register0,
                    dst_type: InstructionParameterType::SPECIAL_REGISTER | InstructionParameterType::BYTE_REGISTER
                })
            },

            0x55 => {
                Ok(Instruction {
                    id: 0x55,
                    mnemonic: "xorb",
                    encoding: EncodingType::RR_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_XOR | _RAnalOpType::R_ANAL_OP_TYPE_REG,
                    esil: "",
                    src_param: InstructionParameter::Register0,
                    src_type: InstructionParameterType::SPECIAL_REGISTER | InstructionParameterType::BYTE_REGISTER,
                    dst_param: InstructionParameter::Memory,
                    dst_type: InstructionParameterType::DIRECT_MEMORY
                })
            },
            _ => {
                let err_str = format!("GOT UNKNOWN OP 0x{:X}", raw_opcode);
                Err(err_str)
            }
        }
    }
}
