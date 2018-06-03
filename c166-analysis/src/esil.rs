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

pub fn process_esil(isn: &Instruction, values: &InstructionArguments, raw_op: *mut RAnalOp)  {

    if isn.esil.is_empty() {
        return
    }

    let out_op : &mut RAnalOp = unsafe {&mut (*raw_op)};

    let mut immed: String = format!("");

    let op1: String = match values.op1.as_ref() {
        Some(Operand::IndirectAndImmediate(ind, im)) => {
            immed = format!("{}", im);
            format!("{}", ind)
        },
        Some(op) => format!("{}", op),
        None => format!("")
    };

    let op2: String = match values.op2.as_ref() {
        Some(Operand::IndirectAndImmediate(ind, im)) => {
            immed = format!("{}", im);
            format!("{}", ind)
        },
        Some(op) => format!("{}", op),
        None => format!("")
    };

    let op3: String = match values.op3.as_ref() {
        Some(op) => format!("{}", op),
        None => format!("")
    };

     match rt_format!(isn.esil, op1=op1, op2=op2, op3=op3, immed=immed) {
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
             eprintln!("Couldn't format ESIL: {}.  ESIL was: {}", error, isn.esil);
         }
     }
}
