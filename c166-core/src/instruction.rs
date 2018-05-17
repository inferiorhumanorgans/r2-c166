// \s+(0x[A-F0-9]+): OpCode\('([a-z_0-9\*]+)', ArgFormat.([A-Za-z_0-9]+), ArgEnc.([A-Za-z_0-9]+), ([A-Z._ |]+).*
// $1 => {\n    Ok(Instruction {\n        id: $1,\n        mnemonic: String::from("$2"),\n        arg_format: String::from("$3"),\n        arg_encoding: String::from("$4"),\n        r2_op_type: $5\n    })\n},\n

use ::r2::_RAnalOpType;

use ::encoding::EncodingType;
use ::opformat::OpFormatType;

pub struct Instruction {
    pub id: u8,
    pub mnemonic: &'static str,
    pub format: OpFormatType,
    pub encoding: EncodingType,
    pub r2_op_type: _RAnalOpType
}

impl Instruction {
    pub fn from_addr_array(bytes: &[u8]) -> Result<Instruction, String> {
        let raw_opcode = bytes[0];

        match raw_opcode {
            0x00 => {
                Ok(Instruction {
                    id: 0x00,
                    mnemonic: "add",
                    format: OpFormatType::Rwn__Rwm,
                    encoding: EncodingType::nm,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_ADD | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0x02 => {
                Ok(Instruction {
                    id: 0x02,
                    mnemonic: "add",
                    format: OpFormatType::reg__mem,
                    encoding: EncodingType::RR_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_ADD | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0x04 => {
                Ok(Instruction {
                    id: 0x04,
                    mnemonic: "add",
                    format: OpFormatType::mem__reg,
                    encoding: EncodingType::RR_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_ADD | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0x06 => {
                Ok(Instruction {
                    id: 0x06,
                    mnemonic: "add",
                    format: OpFormatType::reg__INDdata16,
                    encoding: EncodingType::RR_II_II,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_ADD | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0x08 => {
                Ok(Instruction {
                    id: 0x08,
                    mnemonic: "add",
                    format: OpFormatType::data3_or_reg,
                    encoding: EncodingType::data3_or_reg,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_ADD
                })
            },

            0x01 => {
                Ok(Instruction {
                    id: 0x01,
                    mnemonic: "addb",
                    format: OpFormatType::Rbn__Rbm,
                    encoding: EncodingType::nm,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_ADD | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0x03 => {
                Ok(Instruction {
                    id: 0x03,
                    mnemonic: "addb",
                    format: OpFormatType::breg__mem,
                    encoding: EncodingType::RR_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_ADD | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0x05 => {
                Ok(Instruction {
                    id: 0x05,
                    mnemonic: "addb",
                    format: OpFormatType::mem__breg,
                    encoding: EncodingType::RR_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_ADD | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0x07 => {
                Ok(Instruction {
                    id: 0x07,
                    mnemonic: "addb",
                    format: OpFormatType::breg__INDdata8,
                    encoding: EncodingType::RR_II_xx,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_ADD | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0x09 => {
                Ok(Instruction {
                    id: 0x09,
                    mnemonic: "addb",
                    format: OpFormatType::data3_or_breg,
                    encoding: EncodingType::data3_or_reg,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_ADD
                })
            },

            0x10 => {
                Ok(Instruction {
                    id: 0x10,
                    mnemonic: "addc",
                    format: OpFormatType::Rwn__Rwm,
                    encoding: EncodingType::nm,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_ADD | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0x18 => {
                Ok(Instruction {
                    id: 0x18,
                    mnemonic: "addc",
                    format: OpFormatType::data3_or_reg,
                    encoding: EncodingType::data3_or_reg,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_ADD
                })
            },

            0x16 => {
                Ok(Instruction {
                    id: 0x16,
                    mnemonic: "addc",
                    format: OpFormatType::reg__INDdata16,
                    encoding: EncodingType::RR_II_II,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_ADD | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0x12 => {
                Ok(Instruction {
                    id: 0x12,
                    mnemonic: "addc",
                    format: OpFormatType::reg__mem,
                    encoding: EncodingType::RR_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_ADD | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0x14 => {
                Ok(Instruction {
                    id: 0x14,
                    mnemonic: "addc",
                    format: OpFormatType::mem__reg,
                    encoding: EncodingType::RR_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_ADD | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0x11 => {
                Ok(Instruction {
                    id: 0x11,
                    mnemonic: "addcb",
                    format: OpFormatType::Rbn__Rbm,
                    encoding: EncodingType::nm,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_ADD | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0x19 => {
                Ok(Instruction {
                    id: 0x19,
                    mnemonic: "addcb",
                    format: OpFormatType::data3_or_breg,
                    encoding: EncodingType::data3_or_reg,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_ADD
                })
            },

            0x17 => {
                Ok(Instruction {
                    id: 0x17,
                    mnemonic: "addcb",
                    format: OpFormatType::breg__INDdata8,
                    encoding: EncodingType::RR_II_xx,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_ADD | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0x13 => {
                Ok(Instruction {
                    id: 0x13,
                    mnemonic: "addcb",
                    format: OpFormatType::breg__mem,
                    encoding: EncodingType::RR_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_ADD | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0x15 => {
                Ok(Instruction {
                    id: 0x15,
                    mnemonic: "addcb",
                    format: OpFormatType::mem__breg,
                    encoding: EncodingType::RR_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_ADD | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0x60 => {
                Ok(Instruction {
                    id: 0x60,
                    mnemonic: "and",
                    format: OpFormatType::Rwn__Rwm,
                    encoding: EncodingType::nm,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_AND | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0x68 => {
                Ok(Instruction {
                    id: 0x68,
                    mnemonic: "and",
                    format: OpFormatType::data3_or_reg,
                    encoding: EncodingType::data3_or_reg,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_AND
                })
            },

            0x66 => {
                Ok(Instruction {
                    id: 0x66,
                    mnemonic: "and",
                    format: OpFormatType::reg__INDdata16,
                    encoding: EncodingType::RR_II_II,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_AND | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0x62 => {
                Ok(Instruction {
                    id: 0x62,
                    mnemonic: "and",
                    format: OpFormatType::reg__mem,
                    encoding: EncodingType::RR_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_AND | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0x64 => {
                Ok(Instruction {
                    id: 0x64,
                    mnemonic: "and",
                    format: OpFormatType::mem__reg,
                    encoding: EncodingType::RR_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_AND | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0x61 => {
                Ok(Instruction {
                    id: 0x61,
                    mnemonic: "andb",
                    format: OpFormatType::Rbn__Rbm,
                    encoding: EncodingType::nm,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_AND | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0x69 => {
                Ok(Instruction {
                    id: 0x69,
                    mnemonic: "andb",
                    format: OpFormatType::data3_or_breg,
                    encoding: EncodingType::data3_or_reg,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_AND
                })
            },

            0x67 => {
                Ok(Instruction {
                    id: 0x67,
                    mnemonic: "andb",
                    format: OpFormatType::breg__INDdata8,
                    encoding: EncodingType::RR_II_xx,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_AND | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0x63 => {
                Ok(Instruction {
                    id: 0x63,
                    mnemonic: "andb",
                    format: OpFormatType::breg__mem,
                    encoding: EncodingType::RR_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_AND | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0x65 => {
                Ok(Instruction {
                    id: 0x65,
                    mnemonic: "andb",
                    format: OpFormatType::mem__breg,
                    encoding: EncodingType::RR_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_AND | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0xAC => {
                Ok(Instruction {
                    id: 0xAC,
                    mnemonic: "ashr",
                    format: OpFormatType::Rwn__Rwm,
                    encoding: EncodingType::nm,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_SHR | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0xBC => {
                Ok(Instruction {
                    id: 0xBC,
                    mnemonic: "ashr",
                    format: OpFormatType::Rwn__INDdata4,
                    encoding: EncodingType::In,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_SHR | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0xD1 => {
                Ok(Instruction {
                    id: 0xD1,
                    mnemonic: "atomic_extr",
                    format: OpFormatType::INDirang2,
                    encoding: EncodingType::atomic_extr,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_NULL
                })
            },

            0x6A => {
                Ok(Instruction {
                    id: 0x6A,
                    mnemonic: "band",
                    format: OpFormatType::bitaddrZ_z__bitaddrQ_q,
                    encoding: EncodingType::QQ_ZZ_qz,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_AND
                })
            },

            0x0E => {
                Ok(Instruction {
                    id: 0x0E,
                    mnemonic: "bclr",
                    format: OpFormatType::bitaddrQ_q,
                    encoding: EncodingType::q_QQ,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_AND
                })
            },

            0x1E => {
                Ok(Instruction {
                    id: 0x1E,
                    mnemonic: "bclr",
                    format: OpFormatType::bitaddrQ_q,
                    encoding: EncodingType::q_QQ,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_AND
                })
            },

            0x2E => {
                Ok(Instruction {
                    id: 0x2E,
                    mnemonic: "bclr",
                    format: OpFormatType::bitaddrQ_q,
                    encoding: EncodingType::q_QQ,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_AND
                })
            },

            0x3E => {
                Ok(Instruction {
                    id: 0x3E,
                    mnemonic: "bclr",
                    format: OpFormatType::bitaddrQ_q,
                    encoding: EncodingType::q_QQ,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_AND
                })
            },

            0x4E => {
                Ok(Instruction {
                    id: 0x4E,
                    mnemonic: "bclr",
                    format: OpFormatType::bitaddrQ_q,
                    encoding: EncodingType::q_QQ,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_AND
                })
            },

            0x5E => {
                Ok(Instruction {
                    id: 0x5E,
                    mnemonic: "bclr",
                    format: OpFormatType::bitaddrQ_q,
                    encoding: EncodingType::q_QQ,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_AND
                })
            },

            0x6E => {
                Ok(Instruction {
                    id: 0x6E,
                    mnemonic: "bclr",
                    format: OpFormatType::bitaddrQ_q,
                    encoding: EncodingType::q_QQ,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_AND
                })
            },

            0x7E => {
                Ok(Instruction {
                    id: 0x7E,
                    mnemonic: "bclr",
                    format: OpFormatType::bitaddrQ_q,
                    encoding: EncodingType::q_QQ,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_AND
                })
            },

            0x8E => {
                Ok(Instruction {
                    id: 0x8E,
                    mnemonic: "bclr",
                    format: OpFormatType::bitaddrQ_q,
                    encoding: EncodingType::q_QQ,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_AND
                })
            },

            0x9E => {
                Ok(Instruction {
                    id: 0x9E,
                    mnemonic: "bclr",
                    format: OpFormatType::bitaddrQ_q,
                    encoding: EncodingType::q_QQ,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_AND
                })
            },

            0xAE => {
                Ok(Instruction {
                    id: 0xAE,
                    mnemonic: "bclr",
                    format: OpFormatType::bitaddrQ_q,
                    encoding: EncodingType::q_QQ,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_AND
                })
            },

            0xBE => {
                Ok(Instruction {
                    id: 0xBE,
                    mnemonic: "bclr",
                    format: OpFormatType::bitaddrQ_q,
                    encoding: EncodingType::q_QQ,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_AND
                })
            },

            0xCE => {
                Ok(Instruction {
                    id: 0xCE,
                    mnemonic: "bclr",
                    format: OpFormatType::bitaddrQ_q,
                    encoding: EncodingType::q_QQ,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_AND
                })
            },

            0xDE => {
                Ok(Instruction {
                    id: 0xDE,
                    mnemonic: "bclr",
                    format: OpFormatType::bitaddrQ_q,
                    encoding: EncodingType::q_QQ,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_AND
                })
            },

            0xEE => {
                Ok(Instruction {
                    id: 0xEE,
                    mnemonic: "bclr",
                    format: OpFormatType::bitaddrQ_q,
                    encoding: EncodingType::q_QQ,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_AND
                })
            },

            0xFE => {
                Ok(Instruction {
                    id: 0xFE,
                    mnemonic: "bclr",
                    format: OpFormatType::bitaddrQ_q,
                    encoding: EncodingType::q_QQ,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_AND
                })
            },

            0x2A => {
                Ok(Instruction {
                    id: 0x2A,
                    mnemonic: "bcmp",
                    format: OpFormatType::bitaddrZ_z__bitaddrQ_q,
                    encoding: EncodingType::QQ_ZZ_qz,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CMP
                })
            },

            0x1A => {
                Ok(Instruction {
                    id: 0x1A,
                    mnemonic: "bfldh",
                    format: OpFormatType::bitoffQ__INDmask8__INDdata8,
                    encoding: EncodingType::QQ_AA_II,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_NULL
                })
            },

            0x0A => {
                Ok(Instruction {
                    id: 0x0A,
                    mnemonic: "bfldl",
                    format: OpFormatType::bitoffQ__INDmask8__INDdata8,
                    encoding: EncodingType::QQ_AA_II,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_NULL
                })
            },

            0x4A => {
                Ok(Instruction {
                    id: 0x4A,
                    mnemonic: "bmov",
                    format: OpFormatType::bitaddrZ_z__bitaddrQ_q,
                    encoding: EncodingType::QQ_ZZ_qz,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV
                })
            },

            0x3A => {
                Ok(Instruction {
                    id: 0x3A,
                    mnemonic: "bmovn",
                    format: OpFormatType::bitaddrZ_z__bitaddrQ_q,
                    encoding: EncodingType::QQ_ZZ_qz,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV
                })
            },

            0x5A => {
                Ok(Instruction {
                    id: 0x5A,
                    mnemonic: "bor",
                    format: OpFormatType::bitaddrZ_z__bitaddrQ_q,
                    encoding: EncodingType::QQ_ZZ_qz,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_OR
                })
            },

            0x0F => {
                Ok(Instruction {
                    id: 0x0F,
                    mnemonic: "bset",
                    format: OpFormatType::bitaddrQ_q,
                    encoding: EncodingType::q_QQ,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_OR
                })
            },

            0x1F => {
                Ok(Instruction {
                    id: 0x1F,
                    mnemonic: "bset",
                    format: OpFormatType::bitaddrQ_q,
                    encoding: EncodingType::q_QQ,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_OR
                })
            },

            0x2F => {
                Ok(Instruction {
                    id: 0x2F,
                    mnemonic: "bset",
                    format: OpFormatType::bitaddrQ_q,
                    encoding: EncodingType::q_QQ,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_OR
                })
            },

            0x3F => {
                Ok(Instruction {
                    id: 0x3F,
                    mnemonic: "bset",
                    format: OpFormatType::bitaddrQ_q,
                    encoding: EncodingType::q_QQ,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_OR
                })
            },

            0x4F => {
                Ok(Instruction {
                    id: 0x4F,
                    mnemonic: "bset",
                    format: OpFormatType::bitaddrQ_q,
                    encoding: EncodingType::q_QQ,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_OR
                })
            },

            0x5F => {
                Ok(Instruction {
                    id: 0x5F,
                    mnemonic: "bset",
                    format: OpFormatType::bitaddrQ_q,
                    encoding: EncodingType::q_QQ,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_OR
                })
            },

            0x6F => {
                Ok(Instruction {
                    id: 0x6F,
                    mnemonic: "bset",
                    format: OpFormatType::bitaddrQ_q,
                    encoding: EncodingType::q_QQ,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_OR
                })
            },

            0x7F => {
                Ok(Instruction {
                    id: 0x7F,
                    mnemonic: "bset",
                    format: OpFormatType::bitaddrQ_q,
                    encoding: EncodingType::q_QQ,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_OR
                })
            },

            0x8F => {
                Ok(Instruction {
                    id: 0x8F,
                    mnemonic: "bset",
                    format: OpFormatType::bitaddrQ_q,
                    encoding: EncodingType::q_QQ,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_OR
                })
            },

            0x9F => {
                Ok(Instruction {
                    id: 0x9F,
                    mnemonic: "bset",
                    format: OpFormatType::bitaddrQ_q,
                    encoding: EncodingType::q_QQ,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_OR
                })
            },

            0xAF => {
                Ok(Instruction {
                    id: 0xAF,
                    mnemonic: "bset",
                    format: OpFormatType::bitaddrQ_q,
                    encoding: EncodingType::q_QQ,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_OR
                })
            },

            0xBF => {
                Ok(Instruction {
                    id: 0xBF,
                    mnemonic: "bset",
                    format: OpFormatType::bitaddrQ_q,
                    encoding: EncodingType::q_QQ,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_OR
                })
            },

            0xCF => {
                Ok(Instruction {
                    id: 0xCF,
                    mnemonic: "bset",
                    format: OpFormatType::bitaddrQ_q,
                    encoding: EncodingType::q_QQ,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_OR
                })
            },

            0xDF => {
                Ok(Instruction {
                    id: 0xDF,
                    mnemonic: "bset",
                    format: OpFormatType::bitaddrQ_q,
                    encoding: EncodingType::q_QQ,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_OR
                })
            },

            0xEF => {
                Ok(Instruction {
                    id: 0xEF,
                    mnemonic: "bset",
                    format: OpFormatType::bitaddrQ_q,
                    encoding: EncodingType::q_QQ,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_OR
                })
            },

            0xFF => {
                Ok(Instruction {
                    id: 0xFF,
                    mnemonic: "bset",
                    format: OpFormatType::bitaddrQ_q,
                    encoding: EncodingType::q_QQ,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_OR
                })
            },

            0x7A => {
                Ok(Instruction {
                    id: 0x7A,
                    mnemonic: "bxor",
                    format: OpFormatType::bitaddrZ_z__bitaddrQ_q,
                    encoding: EncodingType::QQ_ZZ_qz,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_XOR
                })
            },

            0xCA => {
                Ok(Instruction {
                    id: 0xCA,
                    mnemonic: "calla",
                    format: OpFormatType::cc__caddr,
                    encoding: EncodingType::c0_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CALL
                })
            },

            0xAB => {
                Ok(Instruction {
                    id: 0xAB,
                    mnemonic: "calli",
                    format: OpFormatType::cc__DREFRwn,
                    encoding: EncodingType::cn,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CALL | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0xBB => {
                Ok(Instruction {
                    id: 0xBB,
                    mnemonic: "callr",
                    format: OpFormatType::rel,
                    encoding: EncodingType::rr,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CALL
                })
            },

            0xDA => {
                Ok(Instruction {
                    id: 0xDA,
                    mnemonic: "calls",
                    format: OpFormatType::seg__caddr,
                    encoding: EncodingType::SS_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CALL
                })
            },

            0x40 => {
                Ok(Instruction {
                    id: 0x40,
                    mnemonic: "cmp",
                    format: OpFormatType::Rwn__Rwm,
                    encoding: EncodingType::nm,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CMP | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0x48 => {
                Ok(Instruction {
                    id: 0x48,
                    mnemonic: "cmp",
                    format: OpFormatType::data3_or_reg,
                    encoding: EncodingType::data3_or_reg,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CMP
                })
            },

            0x46 => {
                Ok(Instruction {
                    id: 0x46,
                    mnemonic: "cmp",
                    format: OpFormatType::reg__INDdata16,
                    encoding: EncodingType::RR_II_II,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CMP | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0x42 => {
                Ok(Instruction {
                    id: 0x42,
                    mnemonic: "cmp",
                    format: OpFormatType::reg__mem,
                    encoding: EncodingType::RR_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CMP | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0x41 => {
                Ok(Instruction {
                    id: 0x41,
                    mnemonic: "cmpb",
                    format: OpFormatType::Rbn__Rbm,
                    encoding: EncodingType::nm,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CMP | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0x49 => {
                Ok(Instruction {
                    id: 0x49,
                    mnemonic: "cmpb",
                    format: OpFormatType::data3_or_breg,
                    encoding: EncodingType::data3_or_reg,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CMP
                })
            },

            0x47 => {
                Ok(Instruction {
                    id: 0x47,
                    mnemonic: "cmpb",
                    format: OpFormatType::breg__INDdata8,
                    encoding: EncodingType::RR_II_xx,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CMP | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0x43 => {
                Ok(Instruction {
                    id: 0x43,
                    mnemonic: "cmpb",
                    format: OpFormatType::breg__mem,
                    encoding: EncodingType::RR_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CMP | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0xA0 => {
                Ok(Instruction {
                    id: 0xA0,
                    mnemonic: "cmpd1",
                    format: OpFormatType::Rwn__INDdata4,
                    encoding: EncodingType::In,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CMP | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0xA6 => {
                Ok(Instruction {
                    id: 0xA6,
                    mnemonic: "cmpd1",
                    format: OpFormatType::Rwn__INDdata16,
                    encoding: EncodingType::Fn_II_II,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CMP | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0xA2 => {
                Ok(Instruction {
                    id: 0xA2,
                    mnemonic: "cmpd1",
                    format: OpFormatType::Rwn__mem,
                    encoding: EncodingType::Fn_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CMP | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0xB0 => {
                Ok(Instruction {
                    id: 0xB0,
                    mnemonic: "cmpd2",
                    format: OpFormatType::Rwn__INDdata4,
                    encoding: EncodingType::In,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CMP | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0xB6 => {
                Ok(Instruction {
                    id: 0xB6,
                    mnemonic: "cmpd2",
                    format: OpFormatType::Rwn__INDdata16,
                    encoding: EncodingType::Fn_II_II,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CMP | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0xB2 => {
                Ok(Instruction {
                    id: 0xB2,
                    mnemonic: "cmpd2",
                    format: OpFormatType::Rwn__mem,
                    encoding: EncodingType::Fn_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CMP | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0x80 => {
                Ok(Instruction {
                    id: 0x80,
                    mnemonic: "cmpi1",
                    format: OpFormatType::Rwn__INDdata4,
                    encoding: EncodingType::In,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CMP | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0x86 => {
                Ok(Instruction {
                    id: 0x86,
                    mnemonic: "cmpi1",
                    format: OpFormatType::Rwn__INDdata16,
                    encoding: EncodingType::Fn_II_II,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CMP | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0x82 => {
                Ok(Instruction {
                    id: 0x82,
                    mnemonic: "cmpi1",
                    format: OpFormatType::Rwn__mem,
                    encoding: EncodingType::Fn_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CMP | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0x90 => {
                Ok(Instruction {
                    id: 0x90,
                    mnemonic: "cmpi2",
                    format: OpFormatType::Rwn__INDdata4,
                    encoding: EncodingType::In,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CMP | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0x96 => {
                Ok(Instruction {
                    id: 0x96,
                    mnemonic: "cmpi2",
                    format: OpFormatType::Rwn__INDdata16,
                    encoding: EncodingType::Fn_II_II,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CMP | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0x92 => {
                Ok(Instruction {
                    id: 0x92,
                    mnemonic: "cmpi2",
                    format: OpFormatType::Rwn__mem,
                    encoding: EncodingType::Fn_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CMP | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0x91 => {
                Ok(Instruction {
                    id: 0x91,
                    mnemonic: "cpl",
                    format: OpFormatType::Rwn,
                    encoding: EncodingType::n0,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CPL | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0xB1 => {
                Ok(Instruction {
                    id: 0xB1,
                    mnemonic: "cplb",
                    format: OpFormatType::Rwn,
                    encoding: EncodingType::n0,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CPL | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0xA5 => {
                Ok(Instruction {
                    id: 0xA5,
                    mnemonic: "diswdt",
                    format: OpFormatType::NO_ARGS,
                    encoding: EncodingType::NO_ARGS4,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_NULL | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0x4B => {
                Ok(Instruction {
                    id: 0x4B,
                    mnemonic: "div",
                    format: OpFormatType::Rwn,
                    encoding: EncodingType::nn,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_DIV | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0x6B => {
                Ok(Instruction {
                    id: 0x6B,
                    mnemonic: "divl",
                    format: OpFormatType::Rwn,
                    encoding: EncodingType::nn,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_DIV | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0x7B => {
                Ok(Instruction {
                    id: 0x7B,
                    mnemonic: "divlu",
                    format: OpFormatType::Rwn,
                    encoding: EncodingType::nn,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_DIV | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0x5B => {
                Ok(Instruction {
                    id: 0x5B,
                    mnemonic: "divu",
                    format: OpFormatType::Rwn,
                    encoding: EncodingType::nn,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_DIV | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0xB5 => {
                Ok(Instruction {
                    id: 0xB5,
                    mnemonic: "einit",
                    format: OpFormatType::NO_ARGS,
                    encoding: EncodingType::NO_ARGS4,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_NULL
                })
            },

            0xD7 => {
                Ok(Instruction {
                    id: 0xD7,
                    mnemonic: "ext*",
                    format: OpFormatType::ext_page_seg,
                    encoding: EncodingType::ext_d7,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_NULL
                })
            },

            0xDC => {
                Ok(Instruction {
                    id: 0xDC,
                    mnemonic: "ext*",
                    format: OpFormatType::Rwm__INDirang2,
                    encoding: EncodingType::ext_dc,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_NULL | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0x87 => {
                Ok(Instruction {
                    id: 0x87,
                    mnemonic: "idle",
                    format: OpFormatType::NO_ARGS,
                    encoding: EncodingType::NO_ARGS4,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_NULL
                })
            },

            0x8A => {
                Ok(Instruction {
                    id: 0x8A,
                    mnemonic: "jb",
                    format: OpFormatType::bitaddrQ_q__rel,
                    encoding: EncodingType::QQ_rr_q0,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_JMP | _RAnalOpType::R_ANAL_OP_TYPE_COND
                })
            },

            0xAA => {
                Ok(Instruction {
                    id: 0xAA,
                    mnemonic: "jbc",
                    format: OpFormatType::bitaddrQ_q__rel,
                    encoding: EncodingType::QQ_rr_q0,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_JMP | _RAnalOpType::R_ANAL_OP_TYPE_COND
                })
            },

            0xEA => {
                Ok(Instruction {
                    id: 0xEA,
                    mnemonic: "jmpa",
                    format: OpFormatType::cc__caddr,
                    encoding: EncodingType::c0_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_JMP | _RAnalOpType::R_ANAL_OP_TYPE_COND
                })
            },

            0x9C => {
                Ok(Instruction {
                    id: 0x9C,
                    mnemonic: "jmpi",
                    format: OpFormatType::cc__DREFRwn,
                    encoding: EncodingType::cn,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_JMP | _RAnalOpType::R_ANAL_OP_TYPE_COND | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0x0D => {
                Ok(Instruction {
                    id: 0x0D,
                    mnemonic: "jmpr",
                    format: OpFormatType::cc__rel,
                    encoding: EncodingType::cc_rr,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_JMP
                })
            },

            0x1D => {
                Ok(Instruction {
                    id: 0x1D,
                    mnemonic: "jmpr",
                    format: OpFormatType::cc__rel,
                    encoding: EncodingType::cc_rr,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_JMP | _RAnalOpType::R_ANAL_OP_TYPE_COND
                })
            },

            0x2D => {
                Ok(Instruction {
                    id: 0x2D,
                    mnemonic: "jmpr",
                    format: OpFormatType::cc__rel,
                    encoding: EncodingType::cc_rr,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_JMP | _RAnalOpType::R_ANAL_OP_TYPE_COND
                })
            },

            0x3D => {
                Ok(Instruction {
                    id: 0x3D,
                    mnemonic: "jmpr",
                    format: OpFormatType::cc__rel,
                    encoding: EncodingType::cc_rr,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_JMP | _RAnalOpType::R_ANAL_OP_TYPE_COND
                })
            },

            0x4D => {
                Ok(Instruction {
                    id: 0x4D,
                    mnemonic: "jmpr",
                    format: OpFormatType::cc__rel,
                    encoding: EncodingType::cc_rr,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_JMP | _RAnalOpType::R_ANAL_OP_TYPE_COND
                })
            },

            0x5D => {
                Ok(Instruction {
                    id: 0x5D,
                    mnemonic: "jmpr",
                    format: OpFormatType::cc__rel,
                    encoding: EncodingType::cc_rr,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_JMP | _RAnalOpType::R_ANAL_OP_TYPE_COND
                })
            },

            0x6D => {
                Ok(Instruction {
                    id: 0x6D,
                    mnemonic: "jmpr",
                    format: OpFormatType::cc__rel,
                    encoding: EncodingType::cc_rr,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_JMP | _RAnalOpType::R_ANAL_OP_TYPE_COND
                })
            },

            0x7D => {
                Ok(Instruction {
                    id: 0x7D,
                    mnemonic: "jmpr",
                    format: OpFormatType::cc__rel,
                    encoding: EncodingType::cc_rr,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_JMP | _RAnalOpType::R_ANAL_OP_TYPE_COND
                })
            },

            0x8D => {
                Ok(Instruction {
                    id: 0x8D,
                    mnemonic: "jmpr",
                    format: OpFormatType::cc__rel,
                    encoding: EncodingType::cc_rr,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_JMP | _RAnalOpType::R_ANAL_OP_TYPE_COND
                })
            },

            0x9D => {
                Ok(Instruction {
                    id: 0x9D,
                    mnemonic: "jmpr",
                    format: OpFormatType::cc__rel,
                    encoding: EncodingType::cc_rr,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_JMP | _RAnalOpType::R_ANAL_OP_TYPE_COND
                })
            },

            0xAD => {
                Ok(Instruction {
                    id: 0xAD,
                    mnemonic: "jmpr",
                    format: OpFormatType::cc__rel,
                    encoding: EncodingType::cc_rr,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_JMP | _RAnalOpType::R_ANAL_OP_TYPE_COND
                })
            },

            0xBD => {
                Ok(Instruction {
                    id: 0xBD,
                    mnemonic: "jmpr",
                    format: OpFormatType::cc__rel,
                    encoding: EncodingType::cc_rr,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_JMP | _RAnalOpType::R_ANAL_OP_TYPE_COND
                })
            },

            0xCD => {
                Ok(Instruction {
                    id: 0xCD,
                    mnemonic: "jmpr",
                    format: OpFormatType::cc__rel,
                    encoding: EncodingType::cc_rr,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_JMP | _RAnalOpType::R_ANAL_OP_TYPE_COND
                })
            },

            0xDD => {
                Ok(Instruction {
                    id: 0xDD,
                    mnemonic: "jmpr",
                    format: OpFormatType::cc__rel,
                    encoding: EncodingType::cc_rr,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_JMP | _RAnalOpType::R_ANAL_OP_TYPE_COND
                })
            },

            0xED => {
                Ok(Instruction {
                    id: 0xED,
                    mnemonic: "jmpr",
                    format: OpFormatType::cc__rel,
                    encoding: EncodingType::cc_rr,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_JMP | _RAnalOpType::R_ANAL_OP_TYPE_COND
                })
            },

            0xFD => {
                Ok(Instruction {
                    id: 0xFD,
                    mnemonic: "jmpr",
                    format: OpFormatType::cc__rel,
                    encoding: EncodingType::cc_rr,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_JMP | _RAnalOpType::R_ANAL_OP_TYPE_COND
                })
            },

            0xFA => {
                Ok(Instruction {
                    id: 0xFA,
                    mnemonic: "jmps",
                    format: OpFormatType::seg__caddr,
                    encoding: EncodingType::SS_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_JMP
                })
            },

            0x9A => {
                Ok(Instruction {
                    id: 0x9A,
                    mnemonic: "jnb",
                    format: OpFormatType::bitaddrQ_q__rel,
                    encoding: EncodingType::QQ_rr_q0,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_JMP | _RAnalOpType::R_ANAL_OP_TYPE_COND
                })
            },

            0xBA => {
                Ok(Instruction {
                    id: 0xBA,
                    mnemonic: "jnbs",
                    format: OpFormatType::bitaddrQ_q__rel,
                    encoding: EncodingType::QQ_rr_q0,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_JMP | _RAnalOpType::R_ANAL_OP_TYPE_COND
                })
            },

            0xF0 => {
                Ok(Instruction {
                    id: 0xF0,
                    mnemonic: "mov",
                    format: OpFormatType::Rwn__Rwm,
                    encoding: EncodingType::nm,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0xE0 => {
                Ok(Instruction {
                    id: 0xE0,
                    mnemonic: "mov",
                    format: OpFormatType::Rwn__INDdata4,
                    encoding: EncodingType::In,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0xE6 => {
                Ok(Instruction {
                    id: 0xE6,
                    mnemonic: "mov",
                    format: OpFormatType::reg__INDdata16,
                    encoding: EncodingType::RR_II_II,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0xA8 => {
                Ok(Instruction {
                    id: 0xA8,
                    mnemonic: "mov",
                    format: OpFormatType::Rwn__DREFRwm,
                    encoding: EncodingType::nm,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0x98 => {
                Ok(Instruction {
                    id: 0x98,
                    mnemonic: "mov",
                    format: OpFormatType::Rwn__DREFRwmINC,
                    encoding: EncodingType::nm,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0xB8 => {
                Ok(Instruction {
                    id: 0xB8,
                    mnemonic: "mov",
                    format: OpFormatType::DREFRwm__Rwn,
                    encoding: EncodingType::nm,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0x88 => {
                Ok(Instruction {
                    id: 0x88,
                    mnemonic: "mov",
                    format: OpFormatType::DREFDECRwm__Rwn,
                    encoding: EncodingType::nm,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0xC8 => {
                Ok(Instruction {
                    id: 0xC8,
                    mnemonic: "mov",
                    format: OpFormatType::DREFRwn__DREFRwm,
                    encoding: EncodingType::nm,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0xD8 => {
                Ok(Instruction {
                    id: 0xD8,
                    mnemonic: "mov",
                    format: OpFormatType::DREFRwnINC__DREFRwm,
                    encoding: EncodingType::nm,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0xE8 => {
                Ok(Instruction {
                    id: 0xE8,
                    mnemonic: "mov",
                    format: OpFormatType::DREFRwn__DREFRwmINC,
                    encoding: EncodingType::nm,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0xD4 => {
                Ok(Instruction {
                    id: 0xD4,
                    mnemonic: "mov",
                    format: OpFormatType::Rwn__DREFRwmINCINDdata16,
                    encoding: EncodingType::nm_II_II,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0xC4 => {
                Ok(Instruction {
                    id: 0xC4,
                    mnemonic: "mov",
                    format: OpFormatType::DREFRwmINCINDdata16__Rwn,
                    encoding: EncodingType::nm_II_II,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0x84 => {
                Ok(Instruction {
                    id: 0x84,
                    mnemonic: "mov",
                    format: OpFormatType::DREFRwn__mem,
                    encoding: EncodingType::_0n_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0x94 => {
                Ok(Instruction {
                    id: 0x94,
                    mnemonic: "mov",
                    format: OpFormatType::mem__DREFRwn,
                    encoding: EncodingType::_0n_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0xF2 => {
                Ok(Instruction {
                    id: 0xF2,
                    mnemonic: "mov",
                    format: OpFormatType::reg__mem,
                    encoding: EncodingType::RR_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0xF6 => {
                Ok(Instruction {
                    id: 0xF6,
                    mnemonic: "mov",
                    format: OpFormatType::mem__reg,
                    encoding: EncodingType::RR_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0xF1 => {
                Ok(Instruction {
                    id: 0xF1,
                    mnemonic: "movb",
                    format: OpFormatType::Rbn__Rbm,
                    encoding: EncodingType::nm,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0xE1 => {
                Ok(Instruction {
                    id: 0xE1,
                    mnemonic: "movb",
                    format: OpFormatType::Rbn__INDdata4,
                    encoding: EncodingType::In,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0xE7 => {
                Ok(Instruction {
                    id: 0xE7,
                    mnemonic: "movb",
                    format: OpFormatType::breg__INDdata8,
                    encoding: EncodingType::RR_II_xx,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0xA9 => {
                Ok(Instruction {
                    id: 0xA9,
                    mnemonic: "movb",
                    format: OpFormatType::Rbn__DREFRwm,
                    encoding: EncodingType::nm,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0x99 => {
                Ok(Instruction {
                    id: 0x99,
                    mnemonic: "movb",
                    format: OpFormatType::Rbn__DREFRwmINC,
                    encoding: EncodingType::nm,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0xB9 => {
                Ok(Instruction {
                    id: 0xB9,
                    mnemonic: "movb",
                    format: OpFormatType::DREFRwm__Rbn,
                    encoding: EncodingType::nm,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0x89 => {
                Ok(Instruction {
                    id: 0x89,
                    mnemonic: "movb",
                    format: OpFormatType::DREFDECRwm__Rbn,
                    encoding: EncodingType::nm,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0xC9 => {
                Ok(Instruction {
                    id: 0xC9,
                    mnemonic: "movb",
                    format: OpFormatType::DREFRwn__DREFRwm,
                    encoding: EncodingType::nm,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0xD9 => {
                Ok(Instruction {
                    id: 0xD9,
                    mnemonic: "movb",
                    format: OpFormatType::DREFRwnINC__DREFRwm,
                    encoding: EncodingType::nm,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0xE9 => {
                Ok(Instruction {
                    id: 0xE9,
                    mnemonic: "movb",
                    format: OpFormatType::DREFRwn__DREFRwmINC,
                    encoding: EncodingType::nm,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0xF4 => {
                Ok(Instruction {
                    id: 0xF4,
                    mnemonic: "movb",
                    format: OpFormatType::Rbn__DREFRwmINCINDdata16,
                    encoding: EncodingType::nm_II_II,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0xE4 => {
                Ok(Instruction {
                    id: 0xE4,
                    mnemonic: "movb",
                    format: OpFormatType::DREFRwmINCINDdata16__Rbn,
                    encoding: EncodingType::nm_II_II,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0xA4 => {
                Ok(Instruction {
                    id: 0xA4,
                    mnemonic: "movb",
                    format: OpFormatType::DREFRwn__mem,
                    encoding: EncodingType::_0n_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0xB4 => {
                Ok(Instruction {
                    id: 0xB4,
                    mnemonic: "movb",
                    format: OpFormatType::mem__DREFRwn,
                    encoding: EncodingType::_0n_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0xF3 => {
                Ok(Instruction {
                    id: 0xF3,
                    mnemonic: "movb",
                    format: OpFormatType::breg__mem,
                    encoding: EncodingType::RR_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0xF7 => {
                Ok(Instruction {
                    id: 0xF7,
                    mnemonic: "movb",
                    format: OpFormatType::mem__breg,
                    encoding: EncodingType::RR_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0xD0 => {
                Ok(Instruction {
                    id: 0xD0,
                    mnemonic: "movbs",
                    format: OpFormatType::Rwn__Rbm,
                    encoding: EncodingType::mn,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0xD2 => {
                Ok(Instruction {
                    id: 0xD2,
                    mnemonic: "movbs",
                    format: OpFormatType::breg__mem,
                    encoding: EncodingType::RR_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0xD5 => {
                Ok(Instruction {
                    id: 0xD5,
                    mnemonic: "movbs",
                    format: OpFormatType::mem__breg,
                    encoding: EncodingType::RR_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0xC0 => {
                Ok(Instruction {
                    id: 0xC0,
                    mnemonic: "movbz",
                    format: OpFormatType::Rwn__Rbm,
                    encoding: EncodingType::mn,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0xC2 => {
                Ok(Instruction {
                    id: 0xC2,
                    mnemonic: "movbz",
                    format: OpFormatType::breg__mem,
                    encoding: EncodingType::RR_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0xC5 => {
                Ok(Instruction {
                    id: 0xC5,
                    mnemonic: "movbz",
                    format: OpFormatType::mem__breg,
                    encoding: EncodingType::RR_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MOV | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0x0B => {
                Ok(Instruction {
                    id: 0x0B,
                    mnemonic: "mul",
                    format: OpFormatType::Rwn__Rwm,
                    encoding: EncodingType::nm,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MUL | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0x1B => {
                Ok(Instruction {
                    id: 0x1B,
                    mnemonic: "mulu",
                    format: OpFormatType::Rwn__Rwm,
                    encoding: EncodingType::nm,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_MUL | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0x81 => {
                Ok(Instruction {
                    id: 0x81,
                    mnemonic: "neg",
                    format: OpFormatType::Rwn,
                    encoding: EncodingType::n0,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CPL | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0xA1 => {
                Ok(Instruction {
                    id: 0xA1,
                    mnemonic: "negb",
                    format: OpFormatType::Rbn,
                    encoding: EncodingType::n0,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CPL | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0xCC => {
                Ok(Instruction {
                    id: 0xCC,
                    mnemonic: "nop",
                    format: OpFormatType::NO_ARGS,
                    encoding: EncodingType::NO_ARGS2,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_NOP
                })
            },

            0x70 => {
                Ok(Instruction {
                    id: 0x70,
                    mnemonic: "or",
                    format: OpFormatType::Rwn__Rwm,
                    encoding: EncodingType::nm,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_OR | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0x78 => {
                Ok(Instruction {
                    id: 0x78,
                    mnemonic: "or",
                    format: OpFormatType::data3_or_reg,
                    encoding: EncodingType::data3_or_reg,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_OR
                })
            },

            0x76 => {
                Ok(Instruction {
                    id: 0x76,
                    mnemonic: "or",
                    format: OpFormatType::reg__INDdata16,
                    encoding: EncodingType::RR_II_II,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_OR | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0x72 => {
                Ok(Instruction {
                    id: 0x72,
                    mnemonic: "or",
                    format: OpFormatType::reg__mem,
                    encoding: EncodingType::RR_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_OR | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0x74 => {
                Ok(Instruction {
                    id: 0x74,
                    mnemonic: "or",
                    format: OpFormatType::mem__reg,
                    encoding: EncodingType::RR_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_OR | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0x71 => {
                Ok(Instruction {
                    id: 0x71,
                    mnemonic: "orb",
                    format: OpFormatType::Rbn__Rbm,
                    encoding: EncodingType::nm,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_OR | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0x79 => {
                Ok(Instruction {
                    id: 0x79,
                    mnemonic: "orb",
                    format: OpFormatType::data3_or_breg,
                    encoding: EncodingType::data3_or_reg,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_OR
                })
            },

            0x77 => {
                Ok(Instruction {
                    id: 0x77,
                    mnemonic: "orb",
                    format: OpFormatType::breg__INDdata8,
                    encoding: EncodingType::RR_II_xx,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_OR | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0x73 => {
                Ok(Instruction {
                    id: 0x73,
                    mnemonic: "orb",
                    format: OpFormatType::breg__mem,
                    encoding: EncodingType::RR_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_OR | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0x75 => {
                Ok(Instruction {
                    id: 0x75,
                    mnemonic: "orb",
                    format: OpFormatType::mem__breg,
                    encoding: EncodingType::RR_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_OR | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0xE2 => {
                Ok(Instruction {
                    id: 0xE2,
                    mnemonic: "pcall",
                    format: OpFormatType::reg__caddr,
                    encoding: EncodingType::RR_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_CALL | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0xFC => {
                Ok(Instruction {
                    id: 0xFC,
                    mnemonic: "pop",
                    format: OpFormatType::reg,
                    encoding: EncodingType::RR,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_POP | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0x2B => {
                Ok(Instruction {
                    id: 0x2B,
                    mnemonic: "prior",
                    format: OpFormatType::Rwn__Rwm,
                    encoding: EncodingType::nm,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_NULL | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0xEC => {
                Ok(Instruction {
                    id: 0xEC,
                    mnemonic: "push",
                    format: OpFormatType::reg,
                    encoding: EncodingType::RR,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_PUSH | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0x97 => {
                Ok(Instruction {
                    id: 0x97,
                    mnemonic: "pwrdn",
                    format: OpFormatType::NO_ARGS,
                    encoding: EncodingType::NO_ARGS4,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_NULL
                })
            },

            0xCB => {
                Ok(Instruction {
                    id: 0xCB,
                    mnemonic: "ret",
                    format: OpFormatType::NO_ARGS,
                    encoding: EncodingType::NO_ARGS2,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_RET
                })
            },

            0xFB => {
                Ok(Instruction {
                    id: 0xFB,
                    mnemonic: "reti",
                    format: OpFormatType::NO_ARGS,
                    encoding: EncodingType::NO_ARGS2,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_RET
                })
            },

            0xEB => {
                Ok(Instruction {
                    id: 0xEB,
                    mnemonic: "retp",
                    format: OpFormatType::reg,
                    encoding: EncodingType::RR,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_RET | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0xDB => {
                Ok(Instruction {
                    id: 0xDB,
                    mnemonic: "rets",
                    format: OpFormatType::NO_ARGS,
                    encoding: EncodingType::NO_ARGS2,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_RET
                })
            },

            0x0C => {
                Ok(Instruction {
                    id: 0x0C,
                    mnemonic: "rol",
                    format: OpFormatType::Rwn__Rwm,
                    encoding: EncodingType::nm,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_ROL | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0x1C => {
                Ok(Instruction {
                    id: 0x1C,
                    mnemonic: "rol",
                    format: OpFormatType::Rwn__INDdata4,
                    encoding: EncodingType::In,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_ROL | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0x2C => {
                Ok(Instruction {
                    id: 0x2C,
                    mnemonic: "ror",
                    format: OpFormatType::Rwn__Rwm,
                    encoding: EncodingType::nm,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_ROR | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0x3C => {
                Ok(Instruction {
                    id: 0x3C,
                    mnemonic: "ror",
                    format: OpFormatType::Rwn__INDdata4,
                    encoding: EncodingType::In,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_ROR | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0xC6 => {
                Ok(Instruction {
                    id: 0xC6,
                    mnemonic: "scxt",
                    format: OpFormatType::reg__INDdata16,
                    encoding: EncodingType::RR_II_II,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_NULL | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0xD6 => {
                Ok(Instruction {
                    id: 0xD6,
                    mnemonic: "scxt",
                    format: OpFormatType::reg__mem,
                    encoding: EncodingType::RR_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_NULL | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0x4C => {
                Ok(Instruction {
                    id: 0x4C,
                    mnemonic: "shl",
                    format: OpFormatType::Rwn__Rwm,
                    encoding: EncodingType::nm,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_SHL | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0x5C => {
                Ok(Instruction {
                    id: 0x5C,
                    mnemonic: "shl",
                    format: OpFormatType::Rwn__INDdata4,
                    encoding: EncodingType::In,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_SHL | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0x6C => {
                Ok(Instruction {
                    id: 0x6C,
                    mnemonic: "shr",
                    format: OpFormatType::Rwn__Rwm,
                    encoding: EncodingType::nm,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_SHR | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0x7C => {
                Ok(Instruction {
                    id: 0x7C,
                    mnemonic: "shr",
                    format: OpFormatType::Rwn__INDdata4,
                    encoding: EncodingType::In,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_SHR | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0xB7 => {
                Ok(Instruction {
                    id: 0xB7,
                    mnemonic: "srst",
                    format: OpFormatType::NO_ARGS,
                    encoding: EncodingType::NO_ARGS4,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_NULL
                })
            },

            0xA7 => {
                Ok(Instruction {
                    id: 0xA7,
                    mnemonic: "srvwdt",
                    format: OpFormatType::NO_ARGS,
                    encoding: EncodingType::NO_ARGS4,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_NULL
                })
            },

            0x20 => {
                Ok(Instruction {
                    id: 0x20,
                    mnemonic: "sub",
                    format: OpFormatType::Rwn__Rwm,
                    encoding: EncodingType::nm,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_SUB | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0x28 => {
                Ok(Instruction {
                    id: 0x28,
                    mnemonic: "sub",
                    format: OpFormatType::data3_or_reg,
                    encoding: EncodingType::data3_or_reg,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_SUB
                })
            },

            0x26 => {
                Ok(Instruction {
                    id: 0x26,
                    mnemonic: "sub",
                    format: OpFormatType::reg__INDdata16,
                    encoding: EncodingType::RR_II_II,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_SUB | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0x22 => {
                Ok(Instruction {
                    id: 0x22,
                    mnemonic: "sub",
                    format: OpFormatType::reg__mem,
                    encoding: EncodingType::RR_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_SUB | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0x24 => {
                Ok(Instruction {
                    id: 0x24,
                    mnemonic: "sub",
                    format: OpFormatType::mem__reg,
                    encoding: EncodingType::RR_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_SUB | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0x21 => {
                Ok(Instruction {
                    id: 0x21,
                    mnemonic: "subb",
                    format: OpFormatType::Rbn__Rbm,
                    encoding: EncodingType::nm,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_SUB | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0x29 => {
                Ok(Instruction {
                    id: 0x29,
                    mnemonic: "subb",
                    format: OpFormatType::data3_or_breg,
                    encoding: EncodingType::data3_or_reg,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_SUB
                })
            },

            0x27 => {
                Ok(Instruction {
                    id: 0x27,
                    mnemonic: "subb",
                    format: OpFormatType::breg__INDdata8,
                    encoding: EncodingType::RR_II_xx,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_SUB | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0x23 => {
                Ok(Instruction {
                    id: 0x23,
                    mnemonic: "subb",
                    format: OpFormatType::breg__mem,
                    encoding: EncodingType::RR_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_SUB | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0x25 => {
                Ok(Instruction {
                    id: 0x25,
                    mnemonic: "subb",
                    format: OpFormatType::mem__breg,
                    encoding: EncodingType::RR_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_SUB | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0x30 => {
                Ok(Instruction {
                    id: 0x30,
                    mnemonic: "subc",
                    format: OpFormatType::Rwn__Rwm,
                    encoding: EncodingType::nm,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_SUB | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0x38 => {
                Ok(Instruction {
                    id: 0x38,
                    mnemonic: "subc",
                    format: OpFormatType::data3_or_reg,
                    encoding: EncodingType::data3_or_reg,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_SUB
                })
            },

            0x36 => {
                Ok(Instruction {
                    id: 0x36,
                    mnemonic: "subc",
                    format: OpFormatType::reg__INDdata16,
                    encoding: EncodingType::RR_II_II,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_SUB | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0x32 => {
                Ok(Instruction {
                    id: 0x32,
                    mnemonic: "subc",
                    format: OpFormatType::reg__mem,
                    encoding: EncodingType::RR_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_SUB | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0x34 => {
                Ok(Instruction {
                    id: 0x34,
                    mnemonic: "subc",
                    format: OpFormatType::mem__reg,
                    encoding: EncodingType::RR_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_SUB | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0x31 => {
                Ok(Instruction {
                    id: 0x31,
                    mnemonic: "subcb",
                    format: OpFormatType::Rbn__Rbm,
                    encoding: EncodingType::nm,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_SUB | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0x39 => {
                Ok(Instruction {
                    id: 0x39,
                    mnemonic: "subcb",
                    format: OpFormatType::data3_or_reg,
                    encoding: EncodingType::data3_or_reg,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_SUB
                })
            },

            0x37 => {
                Ok(Instruction {
                    id: 0x37,
                    mnemonic: "subcb",
                    format: OpFormatType::breg__INDdata8,
                    encoding: EncodingType::RR_II_xx,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_SUB | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0x33 => {
                Ok(Instruction {
                    id: 0x33,
                    mnemonic: "subcb",
                    format: OpFormatType::breg__mem,
                    encoding: EncodingType::RR_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_SUB | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0x35 => {
                Ok(Instruction {
                    id: 0x35,
                    mnemonic: "subcb",
                    format: OpFormatType::mem__breg,
                    encoding: EncodingType::RR_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_SUB | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0x9B => {
                Ok(Instruction {
                    id: 0x9B,
                    mnemonic: "trap",
                    format: OpFormatType::INDtrap7,
                    encoding: EncodingType::trap7,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_TRAP
                })
            },

            0x50 => {
                Ok(Instruction {
                    id: 0x50,
                    mnemonic: "xor",
                    format: OpFormatType::Rwn__Rwm,
                    encoding: EncodingType::nm,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_XOR | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0x58 => {
                Ok(Instruction {
                    id: 0x58,
                    mnemonic: "xor",
                    format: OpFormatType::data3_or_reg,
                    encoding: EncodingType::data3_or_reg,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_XOR
                })
            },

            0x56 => {
                Ok(Instruction {
                    id: 0x56,
                    mnemonic: "xor",
                    format: OpFormatType::reg__INDdata16,
                    encoding: EncodingType::RR_II_II,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_XOR | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0x52 => {
                Ok(Instruction {
                    id: 0x52,
                    mnemonic: "xor",
                    format: OpFormatType::reg__mem,
                    encoding: EncodingType::RR_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_XOR | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0x54 => {
                Ok(Instruction {
                    id: 0x54,
                    mnemonic: "xor",
                    format: OpFormatType::mem__reg,
                    encoding: EncodingType::RR_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_XOR | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0x51 => {
                Ok(Instruction {
                    id: 0x51,
                    mnemonic: "xorb",
                    format: OpFormatType::Rbn__Rbm,
                    encoding: EncodingType::nm,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_XOR | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0x59 => {
                Ok(Instruction {
                    id: 0x59,
                    mnemonic: "xorb",
                    format: OpFormatType::data3_or_breg,
                    encoding: EncodingType::data3_or_reg,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_XOR
                })
            },

            0x57 => {
                Ok(Instruction {
                    id: 0x57,
                    mnemonic: "xorb",
                    format: OpFormatType::breg__INDdata8,
                    encoding: EncodingType::RR_II_xx,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_XOR | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0x53 => {
                Ok(Instruction {
                    id: 0x53,
                    mnemonic: "xorb",
                    format: OpFormatType::breg__mem,
                    encoding: EncodingType::RR_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_XOR | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },

            0x55 => {
                Ok(Instruction {
                    id: 0x55,
                    mnemonic: "xorb",
                    format: OpFormatType::mem__breg,
                    encoding: EncodingType::RR_MM_MM,
                    r2_op_type: _RAnalOpType::R_ANAL_OP_TYPE_XOR | _RAnalOpType::R_ANAL_OP_TYPE_REG
                })
            },
            _ => {
                let err_str = format!("GOT UNKNOWN OP 0x{:X}", raw_opcode);
                Err(err_str)
            }
        }
    }
}
