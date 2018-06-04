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
use std::ffi::CStr;
use std::str;
use std::convert::TryFrom;

use c166_core::r2::*;
use c166_core::instruction::*;
use c166_core::encoding::*;
use c166_core::parser::*;

lazy_static! {
    static ref OP_LUT: OpLookUpTable<'static> = {
        let mut op_lut: OpLookUpTable = OpLookUpTable::new();
        build_lut(&mut op_lut);
        op_lut
    };
}

pub extern "C" fn c166_assemble(_asm: *mut RAsm, raw_op: *mut RAsmOp, buf: *const c_char) -> i32 {
    let op_lut: &OpLookUpTable = &OP_LUT;

    let c_str: &CStr = unsafe { CStr::from_ptr(buf) };
    let mut init_data: &[u8] = c_str.to_bytes_with_nul();
    let data: &str = str::from_utf8(init_data).unwrap();
    let out_op : &mut RAsmOp = unsafe {&mut (*raw_op)};

    out_op.size = 0;
        match asm_lines(data) {
        Ok((remainder, ops)) => {
            for op in ops {
                eprintln!("");
                eprintln!("OP: {:?}", op);

                match operation_to_bytes(&op, &op_lut) {
                    Ok(out_bytes) => {
                        eprintln!("OKAY: {:X?}", out_bytes);
                        for byte in out_bytes.iter() {
                            if out_op.size < R_ASM_BUFSIZE as i32 {
                                out_op.buf[out_op.size as usize] = *byte;
                                out_op.size += 1;
                            } else {
                                panic!("Not enough room, max len is 0x{:X}", R_ASM_BUFSIZE);
                            }
                        }
                    },
                    Err(msg) => {
                        eprintln!("ASM: {:?}", data);
                        eprintln!("ERROR: {:?}", msg);
                    },
                }
            }
        },
        Err(e) => {
            eprintln!("ERR: {:?}", e)
        }
    };

    out_op.size
}
