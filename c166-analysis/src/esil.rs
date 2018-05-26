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

use std::ffi::CString;

use c166_core::r2::*;
use c166_core::instruction::*;
use c166_core::encoding::*;
use c166_core::register::*;

pub fn register_to_esil(some_reg: Option<u8>, reg_type: &InstructionParameterType) -> String {
    let register : u8 = some_reg.unwrap();

    if reg_type.intersects(InstructionParameterType::GENERAL_REGISTER) {
        get_gpr_mnem(register, reg_type.intersects(InstructionParameterType::BYTE_REGISTER))
    } else if reg_type.intersects(InstructionParameterType::SPECIAL_REGISTER) {
        get_register_mnem(register, reg_type.intersects(InstructionParameterType::BYTE_REGISTER))
    } else {
        format!("")
    }
}

pub fn immediate_to_esil(data: Option<u16>) -> String {
    match data {
        Some(value) => format!("{}", value),
        None => format!("")
    }
}

pub fn process_esil(op: &Instruction, values: &InstructionArguments, raw_op: *mut RAnalOp)  {
    if op.esil.is_empty() {
        return
    }

    let out_op : &mut RAnalOp = unsafe {&mut (*raw_op)};

    let reg0 : String;
    let reg1 : String;

    if op.src_param == InstructionParameter::Register0 {
        reg0 = register_to_esil(values.register0, &op.src_type);
    } else if op.dst_param == InstructionParameter::Register0 {
        reg0 = register_to_esil(values.register0, &op.dst_type);
    } else {
        reg0 = format!("");
    }

    if op.src_param == InstructionParameter::Register1 {
        reg1 = register_to_esil(values.register1, &op.src_type);
    } else if op.dst_param == InstructionParameter::Register1 {
        reg1 = register_to_esil(values.register1, &op.dst_type);
    } else {
        reg1 = format!("");
    }

    let immed : String = immediate_to_esil(values.data);

    match rt_format!(op.esil, reg0=reg0, reg1=reg1, immed=immed) {
        Ok(esil_string) => {
            match CString::new(esil_string) {
                Ok(esil_cstring) => {
                    unsafe {
                        let esil_buf = &mut out_op.esil;
                        r_strbuf_init(esil_buf);
                        r_strbuf_append(esil_buf, esil_cstring.as_ptr());
                    }
                },
                Err(_) => {}
            }
        },
        Err(error) => {
            eprintln!("Couldn't format ESIL: {}.  ESIL was: {}", error, op.esil);
        }
    }
}
