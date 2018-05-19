extern crate c166_core;

use std::os::raw::c_void;
use std::os::raw::c_char;
use std::ptr;

use c166_core::r2::*;
use c166_core::instruction::Instruction;
use c166_core::encoding::Encoding;
use c166_core::opformat::OpFormat;

// https://github.com/rust-lang/rfcs/issues/400
macro_rules! cstr {
  ($s:expr) => (
    concat!($s, "\0") as *const str as *const [c_char] as *const c_char
  );
}
const EMPTY_STRING : *const c_char = b"\0" as *const [u8] as *const c_char;

extern "C" fn c166_disassemble(_asm: *mut RAsm, raw_op: *mut RAsmOp, buf: *const u8, len: i32) -> i32 {
        let out_op : &mut RAsmOp;
        let bytes;

        unsafe {
            out_op = &mut (*raw_op);
            bytes = std::slice::from_raw_parts(buf as *const u8, len as usize);
        }


        match Instruction::from_addr_array(bytes) {
            Ok(op) => {
                let encoding = Encoding::from_encoding_type(&op.encoding).unwrap();

                if encoding.length <= len {
                    let format = OpFormat::from_format_type(&op.format).unwrap();

                    // https://github.com/rust-lang/rust/issues/18343
                    match (encoding.decode)(bytes) {
                        Ok(values) => {
                            let desc = (format.decode)(&op, values);

                            out_op.size = encoding.length;
                            out_op.payload = 0;
                            out_op.buf_asm[desc.len()] = 0;

                            unsafe {
                                std::ptr::copy(desc.as_bytes() as *const [u8] as *const c_char, &mut out_op.buf_asm as *mut [c_char] as *mut c_char, desc.len());
                            }
                        },
                        Err(_) => {
                            out_op.size = -1;
                            out_op.payload = 0;
                            out_op.buf_asm[0] = 0;
                        }
                    }
                } else {
                    out_op.size = -1;
                    out_op.payload = 0;
                    out_op.buf_asm[0] = 0;
                }
            },
            Err(_) => {
                out_op.size = -1;
                out_op.payload = 0;
                out_op.buf_asm[0] = 0;
            }
        }

        return out_op.size;
}

#[allow(non_upper_case_globals)]
const C166_ASM_PLUGIN: RAsmPlugin = RAsmPlugin {
    name:           cstr!("c166"),
    arch:           cstr!("c166"),
    author:         cstr!("inferiorhumanorgans"),
    version:        cstr!("0.1.0"),
    license:        cstr!("GPL3"),
    user:           ptr::null_mut(),
    cpus:           EMPTY_STRING,
    desc:           cstr!("c166 disassembler"),
    bits:           16,
    endian:         0,
    disassemble:    Some(c166_disassemble),
    assemble:       None,
    init:           None,
    fini:           None,
    modify:         None,
    set_subarch:    None,
    mnemonics:      None,
    features:       EMPTY_STRING,
};

#[no_mangle]
#[allow(non_upper_case_globals)]
pub static mut radare_plugin: RLibStruct = RLibStruct {
    type_:  R_LIB_TYPE_ASM as i32,
    data:   ((&C166_ASM_PLUGIN) as *const RAsmPlugin) as *mut c_void,
    version:R2_VERSION as *const [u8] as *const c_char,
    free:   None
};
