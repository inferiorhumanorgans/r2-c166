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
            0x00 => {
                Ok(Instruction {
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

            0x01 => {
                Ok(Instruction {
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

            0x10 => {
                Ok(Instruction {
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

            0x11 => {
                Ok(Instruction {
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

            0x60 => {
                Ok(Instruction {
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

            0x61 => {
                Ok(Instruction {
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

            0xAC => {
                Ok(Instruction {
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

            0xD1 => {
                Ok(Instruction {
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

            0x6A => {
                Ok(Instruction {
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

            0x0E => {
                Ok(Instruction {
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

            0x2A => {
                Ok(Instruction {
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

            0x1A => {
                Ok(Instruction {
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

            0x0A => {
                Ok(Instruction {
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

            0x4A => {
                Ok(Instruction {
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

            0x3A => {
                Ok(Instruction {
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

            0x5A => {
                Ok(Instruction {
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

            0xC0 => {
                Ok(Instruction {
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

            0x0B => {
                Ok(Instruction {
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

            0x1B => {
                Ok(Instruction {
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
