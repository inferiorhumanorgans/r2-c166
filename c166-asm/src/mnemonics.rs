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
use std::ptr;
use std::os::raw::c_char;
use std::convert::TryFrom;

use c166_core::r2::*;
use c166_core::instruction::Instruction;

pub extern "C" fn c166_mnemonic_by_id(_raw_asm: *mut RAsm, op_id: i32, is_json: bool) -> *mut c_char {
    if op_id == -1 {
        let mut opcodes : Vec<&str> = Vec::with_capacity(0xFF);
        for n in 0x00..=0xFF {
            if let Ok(op) = Instruction::try_from(n as u8) {
                opcodes.push(op.mnemonic);
            }
        }

        opcodes.push(""); // Gotta have that trailing newline

        let string : String = opcodes.join("\n");
        let c_string = CString::new(string).unwrap();

        return unsafe { r_str_new (c_string.as_ptr()) }
    }

    if op_id > <u8>::max_value() as i32 {
        return ptr::null_mut();
    }

    match Instruction::try_from(op_id as u8) {
        Ok(op) => {
            // r2 wants a newline terminated string... :/
            let c_string = match is_json {
                true => CString::new(format!("[\"{}\"]\n", op.mnemonic)).unwrap(),
                false => CString::new(format!("{}\n", op.mnemonic)).unwrap()
            };

            return unsafe { r_str_new (c_string.as_ptr()) };
        },
        Err(_) => {
            return ptr::null_mut();
        }
    }
}
