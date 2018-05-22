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

fn format_esil_param(param: &InstructionParameter, param_type: &InstructionParameterType, values: &InstructionArguments) -> String {
    if param_type.intersects(InstructionParameterType::GENERAL_REGISTER) {
        if *param == InstructionParameter::Register0 {
            return get_gpr_mnem(values.register0.unwrap(), param_type.intersects(InstructionParameterType::BYTE_REGISTER));
        } else {
            return get_gpr_mnem(values.register1.unwrap(), param_type.intersects(InstructionParameterType::BYTE_REGISTER));
        }
    } else if param_type.intersects(InstructionParameterType::SPECIAL_REGISTER) {
        if *param == InstructionParameter::Register0 {
            return get_register_mnem(values.register0.unwrap(), param_type.intersects(InstructionParameterType::BYTE_REGISTER));
        } else {
            return get_register_mnem(values.register1.unwrap(), param_type.intersects(InstructionParameterType::BYTE_REGISTER));
        }
    } else if param_type.intersects(InstructionParameterType::IMMEDIATE) && !param_type.intersects(InstructionParameterType::INDIRECT) {
        return format!("{}", values.data.unwrap());
    }

    String::from("")
}

pub fn process_esil(op: &Instruction, bytes: &[u8], raw_op: *mut RAnalOp)  {
    if op.esil.is_empty() {
        return
    }

    let out_op : &mut RAnalOp = unsafe {&mut (*raw_op)};
    let encoding = Encoding::from_encoding_type(&op.encoding).unwrap();

    match (encoding.decode)(bytes) {
        Ok(values) => {

            let mut dest : String = format_esil_param(&op.dst_param, &op.dst_type, &values);
            let mut src : String = format_esil_param(&op.src_param, &op.src_type, &values);

            match rt_format!(op.esil, src=src, dest=dest) {
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
                Err(_) => {}
            }
        },
        Err(_) => {} // Op not found
    }
}
