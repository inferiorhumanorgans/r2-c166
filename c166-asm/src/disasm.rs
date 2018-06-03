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

use std::os::raw::c_char;
use std::{ptr,slice};
use std::convert::TryFrom;

use c166_core::r2::*;
use c166_core::instruction::Instruction;
use c166_core::encoding::Encoding;
use c166_core::opformat::*;

pub extern "C" fn c166_disassemble(raw_asm: *mut RAsm, raw_op: *mut RAsmOp, buf: *const u8, _len: i32) -> i32 {
    let asm : &RAsm;
    let out_op : &mut RAsmOp;
    let bytes;

    unsafe {
        asm = &(*raw_asm);
        out_op = &mut (*raw_op);

        bytes = slice::from_raw_parts(buf as *const u8, 4 as usize);
    }

    match Instruction::try_from(bytes) {
        Ok(op) => {
            let encoding = Encoding::from(&op.encoding);

            // https://github.com/rust-lang/rust/issues/18343
            match (encoding.decode)(&op, bytes) {
                Ok(values) => {
                    if asm.pc > <u32>::max_value() as u64 {
                        out_op.size = -1;
                        out_op.payload = 0;
                        out_op.buf_asm[0] = 0;
                    } else {
                        let desc = format_op(&op, &values, asm.pc as u32);

                        out_op.size = encoding.length;
                        out_op.payload = 0;
                        out_op.buf_asm[desc.len()] = 0;

                        unsafe {
                            ptr::copy(desc.as_bytes() as *const [u8] as *const c_char, &mut out_op.buf_asm as *mut [c_char] as *mut c_char, desc.len());
                        }
                    }
                    out_op.size
                },
                Err(_) => {
                    out_op.size = -1;
                    out_op.payload = 0;
                    out_op.buf_asm[0] = 0;
                    out_op.size
                }
            }
        },
        Err(_) => {
            out_op.size = -1;
            out_op.payload = 0;
            out_op.buf_asm[0] = 0;

            out_op.size
        }
    }
}
