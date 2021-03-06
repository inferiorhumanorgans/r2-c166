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

#![feature(try_from)]

#[macro_use]
extern crate runtime_fmt;

extern crate c166_core;

use std::os::raw::c_void;
use std::os::raw::c_char;
use std::convert::TryFrom;

use c166_core::r2::*;
use c166_core::instruction::*;
use c166_core::encoding::*;

mod annotations;
use annotations::*;

mod esil;
use esil::*;

// https://github.com/rust-lang/rfcs/issues/400
macro_rules! cstr_mut {
  ($s:expr) => (
    concat!($s, "\0") as *const str as *const [c_char] as *mut c_char
  );
}

macro_rules! cstr {
  ($s:expr) => (
    concat!($s, "\0") as *const str as *const [c_char] as *const c_char
  );
}

fn condition_to_r2(condition: &OpCondition) -> _RAnalCond {
    match condition {
        OpCondition::cc_UC  => _RAnalCond::R_ANAL_COND_AL,
        OpCondition::cc_NET => _RAnalCond::R_ANAL_COND_NE,
        OpCondition::cc_Z   => _RAnalCond::R_ANAL_COND_EQ,
        OpCondition::cc_NZ  => _RAnalCond::R_ANAL_COND_NE,
        OpCondition::cc_V   => _RAnalCond::R_ANAL_COND_VS,
        OpCondition::cc_NV  => _RAnalCond::R_ANAL_COND_VC,
        OpCondition::cc_N   => _RAnalCond::R_ANAL_COND_MI,
        OpCondition::cc_NN  => _RAnalCond::R_ANAL_COND_PL,
        OpCondition::cc_C   => _RAnalCond::R_ANAL_COND_HS,
        OpCondition::cc_NC  => _RAnalCond::R_ANAL_COND_LO,
        OpCondition::cc_SGT => _RAnalCond::R_ANAL_COND_GT,
        OpCondition::cc_SLE => _RAnalCond::R_ANAL_COND_LE,
        OpCondition::cc_SLT => _RAnalCond::R_ANAL_COND_LT,
        OpCondition::cc_SGE => _RAnalCond::R_ANAL_COND_GE,
        OpCondition::cc_UGT => _RAnalCond::R_ANAL_COND_HI,
        OpCondition::cc_ULE => _RAnalCond::R_ANAL_COND_LS,
    }
}

extern "C" fn c166_set_reg_profile(a: *mut RAnal) -> i32 {
    let anal : &mut RAnal;
    let ret : i32;

    let profile = cstr!("\
        =SP     sp\n\
        =PC     pc\n\
        gpr     r0          .16     0       0\n\
        gpr     rl0         .8      0       0\n\
        gpr     rh0         .8      1       0\n\
        gpr     r1          .16     2       0\n\
        gpr     rl1         .8      2       0\n\
        gpr     rh1         .8      3       0\n\
        gpr     r2          .16     4       0\n\
        gpr     rl2         .8      4       0\n\
        gpr     rh2         .8      5       0\n\
        gpr     r3          .16     6       0\n\
        gpr     rl3         .8      6       0\n\
        gpr     rh3         .8      7       0\n\
        gpr     r4          .16     8       0\n\
        gpr     rl4         .8      8       0\n\
        gpr     rh4         .8      9       0\n\
        gpr     r5          .16     10      0\n\
        gpr     r6          .16     12      0\n\
        gpr     r7          .16     14      0\n\
        gpr     r8          .16     16      0\n\
        gpr     r9          .16     18      0\n\
        gpr     r10         .16     20      0\n\
        gpr     r11         .16     22      0\n\
        gpr     r12         .16     24      0\n\
        gpr     r13         .16     26      0\n\
        gpr     r14         .16     28      0\n\
        gpr     r15         .16     30      0\n\

        gpr     sp          .16     32      0\n\

        gpr     pc          .16     34      0\n\

        gpr     addrsel1    .16     36      0\n\
        gpr     addrsel2    .16     38      0\n\
        gpr     addrsel3    .16     40      0\n\
        gpr     addrsel4    .16     42      0\n\

        gpr     buscon0     .16     44      0\n\
        gpr     buscon1     .16     46      0\n\
        gpr     buscon2     .16     48      0\n\
        gpr     buscon3     .16     50      0\n\
        gpr     buscon4     .16     52      0\n\

        gpr     cp          .16     54      0\n\

        seg     csp         .16     56      0\n\

        seg     dpp0        .16     58      0\n\
        seg     dpp1        .16     60      0\n\
        seg     dpp2        .16     62      0\n\
        seg     dpp3        .16     64      0\n\

        gpr     mdc         .16     66      0\n\
        gpr     mdh         .8      68      0\n\
        gpr     mdl         .8      69      0\n\

        gpr     psw         .16     70      0\n\
        flg     e           .1      70.4    0\n\
        flg     z           .1      70.3    0\n\
        flg     v           .1      70.2    0\n\
        flg     c           .1      70.1    0\n\
        flg     n           .1      70.0    0\n\

        gpr     s0bg        .16     72      0\n\
        gpr     s0con       .16     74      0\n\
        gpr     s0eic       .16     76      0\n\
        gpr     s0rbuf      .16     78      0\n\
        gpr     s0ric       .16     80      0\n\
        gpr     s0tbic      .16     82      0\n\
        gpr     s0tbuf      .16     84      0\n\
        gpr     s0tic       .16     86      0\n\

        gpr     syscon      .16     88      0\n\
    ");

    unsafe {
        anal = &mut (*a);
        ret = r_reg_set_profile_string(anal.reg, profile);
    }

    ret
}

extern "C" fn c166_archinfo(_anal: *mut RAnal, query: i32) -> i32 {
    match query as u32 {
        R_ANAL_ARCHINFO_ALIGN => -1,
        R_ANAL_ARCHINFO_MAX_OP_SIZE => 4,
        R_ANAL_ARCHINFO_MIN_OP_SIZE => 2,
        _ => panic!("Query must be one of: R_ANAL_ARCHINFO_ALIGN={}, R_ANAL_ARCHINFO_MAX_OP_SIZE={}, R_ANAL_ARCHINFO_MIN_OP_SIZE={}, got {}",
                R_ANAL_ARCHINFO_ALIGN, R_ANAL_ARCHINFO_MAX_OP_SIZE, R_ANAL_ARCHINFO_MIN_OP_SIZE, query)
    }
}

extern "C" fn c166_op(an: *mut RAnal, raw_op: *mut RAnalOp, pc: u64, buf: *const u8, _len: i32) -> i32 {
    let out_op : &mut RAnalOp;
    let bytes : &[u8];

    unsafe {
        out_op = &mut (*raw_op);
        // Gross.
        bytes = std::slice::from_raw_parts(buf as *const u8, 4 as usize);
    }

    match Instruction::try_from(bytes) {
        Ok(isn) => {
            let encoding = Encoding::from(&isn.encoding);

            out_op.id = bytes[0] as i32;
            out_op.nopcode = 1;
            out_op.family = R_ANAL_OP_FAMILY_CPU; // TODO: set privileged as appropriate
            out_op.type_ = isn.r2_op_type.uint_value();
            out_op.size = encoding.length;

            out_op.addr = pc;

            let op_type = _RAnalOpType(0x000000FF & out_op.type_);

            match op_type {
                _RAnalOpType::R_ANAL_OP_TYPE_RET => {
                    out_op.eob = true;
                },
                _RAnalOpType::R_ANAL_OP_TYPE_JMP | _RAnalOpType::R_ANAL_OP_TYPE_CALL => {
                    // Always go to the next instruction on failure
                    out_op.fail = pc + (out_op.size as u64);

                    match (encoding.decode)(&isn, bytes) {
                        Ok(values) => {
                            out_op.cond = match values.op1.as_ref().unwrap() {
                                &Operand::Condition(ref condition) => condition_to_r2(condition).uint_value() as i32,
                                _ => 0
                            };

                            if out_op.cond == 0 {
                                out_op.eob = true;
                            }

                            match (isn.op2, values.op2) {
                                (Some(OperandType::DirectCaddr16), Some(Operand::Direct(d, _width))) => {
                                    match (isn.op1.as_ref().unwrap(), values.op1.as_ref().unwrap()) {
                                        (OperandType::DirectSegment8, Operand::Direct(seg, _width)) => {
                                            // grab from op1 Some(seg) => (0x10000 * seg as u64) + (address as u64),
                                            out_op.jump = (0x10000 * *seg as u64) + (d as u64)
                                        },
                                        _ => out_op.jump = d as u64
                                    };
                                },
                                (Some(OperandType::DirectRelative8S), Some(Operand::Direct(d, _width))) => {
                                    // TODO: Grab size of next op instead of hardcoding it to 2
                                    out_op.jump = pc + ( ((d as u64)+1) * 2 );
                                }
                                _ => {}
                            };
                        },
                        Err(_) => {
                            out_op.id = -1;
                                out_op.size = -1;
                            out_op.type_ = _RAnalOpType::R_ANAL_OP_TYPE_ILL.uint_value();
                        }
                    }
                },
                _ => {}
            }

            match (encoding.decode)(&isn, bytes) {
                Ok(values) => {
                    annotate_sfr_ops(&isn, &values, an, pc);
                    process_esil(&isn, &values, raw_op);
                },
                _ => {}
            }
        },
        Err(_) => {
            out_op.id = -1;
            out_op.size = -1;
            out_op.type_ = _RAnalOpType::R_ANAL_OP_TYPE_ILL.uint_value();
        }
    }

    out_op.size
}

const C166_ANALYSIS_PLUGIN: RAnalPlugin = RAnalPlugin {
    name:               cstr_mut!("c166"),
    desc:               cstr_mut!("c166 analysis plugin"),
    license:            cstr_mut!("GPL3"),
    arch:               cstr_mut!("c166"),
    author:             cstr_mut!("inferiorhumanorgans"),
    version:            cstr_mut!(env!("CARGO_PKG_VERSION")),
    bits:               16,
    esil:               0,
    fileformat_type:    0,
    custom_fn_anal:     0,
    init:               None,
    fini:               None,
    reset_counter:      None,
    archinfo:           Some(c166_archinfo),
    anal_mask:          None,
    op:                 Some(c166_op),
    bb:                 None,
    fcn:                None,
    analyze_fns:        None,
    op_from_buffer:     None, // Does anyone use this?
    bb_from_buffer:     None,
    fn_from_buffer:     None,
    analysis_algorithm: None,
    pre_anal:           None,
    pre_anal_fn_cb:     None,
    pre_anal_op_cb:     None,
    post_anal_op_cb:    None,
    pre_anal_bb_cb:     None,
    post_anal_bb_cb:    None,
    post_anal_fn_cb:    None,
    post_anal:          None,
    revisit_bb_anal:    None,
    cmd_ext:            None,
    set_reg_profile:    Some(c166_set_reg_profile),
    get_reg_profile:    None,
    fingerprint_bb:     None,
    fingerprint_fcn:    None,
    diff_bb:            None,
    diff_fcn:           None,
    diff_eval:          None,
    is_valid_offset:    None,
    esil_init:          None,
    esil_post_loop:     None,
    esil_intr:          None,
    esil_trap:          None,
    esil_fini:          None
};

#[no_mangle]
#[allow(non_upper_case_globals)]
pub static mut radare_plugin: RLibStruct = RLibStruct {
    type_:  R_LIB_TYPE_ANAL as i32,
    data:   ((&C166_ANALYSIS_PLUGIN) as *const RAnalPlugin) as *mut c_void,
    version:R2_VERSION as *const [u8] as *const c_char,
    free:   None
};
