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
use c166_core::register::*;
use c166_core::r2::*;
use c166_core::encoding::*;
use c166_core::instruction::*;

// Assume 20MHz
const CLOCK_RATE : u32 = 20000000;

fn add_comments_at_address(an: *mut RAnal, addr: u64, strings: &Vec<String>) {
    let comment = strings.join("\n");
    let cstring : CString = CString::new(comment).unwrap();
    unsafe {
        r_meta_set_string(an, R_META_TYPE_COMMENT, addr, cstring.as_ptr());
    }
}

fn format_s0bg(value: u16) -> String {
    let mut strings : Vec<String> = Vec::new();

    let real_baud_1 : u32 = ( CLOCK_RATE ) / ( 16 * (2 + 0) * (value as u32) + 1);
    let real_baud_2 : u32 = ( CLOCK_RATE ) / ( 16 * (2 + 1) * (value as u32) + 1);
    
    strings.push(format!("Actual baud rate = {} (S0BRS = 0)", real_baud_1));
    strings.push(format!("Actual baud rate = {} (S0BRS = 1)", real_baud_2));
    let assumed_baud : Option<u32> = match value {
        0x0000 => Some(625000),
        0x001F | 0x0020 | 0x0014 | 0x0015 => Some(19200),
        0x0040 | 0x0041 | 0x002A | 0x002B => Some(9600),
        0x0081 | 0x0082 | 0x0055 | 0x0056 => Some(4800),
        0x0103 | 0x0104 | 0x00AC | 0x00AD => Some(2400),
        0x0207 | 0x0208 | 0x015A | 0x015B => Some(1200),
        0x0410 | 0x0411 | 0x02B5 | 0x02B6 => Some(600),
        0x1FFF | 0x15B2 | 0x15B3 => Some(75),
        _ => None
    };

    match assumed_baud {
        Some(baud) => strings.push(format!("Intended baud rate = {}", baud)),
        _ => {}
    }

    strings.join("\n")
}

fn format_s0con(value: u16) -> String {
    let mut strings : Vec<String> = Vec::new();

    let mut data_bits : Option<char> = None;
    let mut is_sync : bool = false;
    let mut is_parity : bool = false;
    let mut is_wakeup : bool = false;

    let parity_type = match value & 0x1000 {
        0 => 'E',
        _ => 'O'
    };

    match value & 0x07 {
        0x00 => {
            data_bits = Some('8');
            is_sync = true;
        },
        0x01 => {
            data_bits = Some('8');
        },
        0x02 => {}, // ???
        0x03 => {
            data_bits = Some('7');
            is_parity = true;
        },
        0x04 => {
            data_bits = Some('9');
        },
        0x05 => {
            data_bits = Some('8');
            is_wakeup = true;
        },
        0x06 => {}, // ???
        0x07 => {
            data_bits = Some('8');
            is_parity = true;
        },
        _ => {}
    };

    let parity = match is_parity {
        true => parity_type,
        _ => 'N'
    };

    let stop_bits = match value & 0x08 {
        0 => 1,
        _ => 2
    };

    let data_char : char = match data_bits {
        Some(d) => d,
        _ => '?'
    };

    let wakeup_str = match is_wakeup {
        true => " + wakeup",
        _ => ""
    };

    let sync_str = match is_sync {
        true => " + sync",
        _ => ""
    };

    strings.push(format!("Data = {}{}{}{}{}", data_char, parity, stop_bits, sync_str, wakeup_str));

    match value & 0x0010 {
        0 => strings.push(String::from("Disable S0 receiver")),
        _ => strings.push(String::from("Enable S0 receiver"))
    };

    match value & 0x0020 {
        0 => strings.push(String::from("Ignore parity")),
        _ => strings.push(String::from("Check parity"))
    };

    match value & 0x0040 {
        0 => strings.push(String::from("Ignore framing errors")),
        _ => strings.push(String::from("Check framing errors"))
    };

    match value & 0x0080 {
        0 => strings.push(String::from("Ignore overrun errors")),
        _ => strings.push(String::from("Check overrun errors"))
    };

    match value & 0x0100 {
        0 => {},
        _ => strings.push(String::from("ACK parity error"))
    };

    match value & 0x0200 {
        0 => {},
        _ => strings.push(String::from("ACK framing error"))
    };

    match value & 0x0400 {
        0 => {},
        _ => strings.push(String::from("ACK overrun error"))
    };

    match value & 0x2000 {
        0 => strings.push(String::from("S0BRS = 0, Divide clock by reload-value + constant (depending on mode)")),
        _ => strings.push(String::from("S0BRS = 1, Additionally reduce serial clock to 2/3rd"))
    };

    match value & 0x4000 {
        0 => strings.push(String::from("Loopback mode disabled")),
        _ => strings.push(String::from("Loopback mode enabled"))
    };

    match value & 0x8000 {
        0 => strings.push(String::from("Baudrate generator disabled (ASC0 inactive)")),
        _ => strings.push(String::from("Baudrate generator enabled"))
    };

    strings.join("\n")
}

fn format_adcon(value: u16) -> String {
    let mut strings : Vec<String> = Vec::new();

    strings.push(format!("ADC Channel {:X}", (value & 0x000F)));

    // ADC mode
    match value & 0x30 {
        0x00 => strings.push(String::from("Fixed Channel Single Conversion")),
        0x01 => strings.push(String::from("Fixed Channel Continuous Conversion")),
        0x02 => strings.push(String::from("Auto Scan Single Conversion")),
        0x03 => strings.push(String::from("Auto Scan Continuous Conversion")),
        _ => {}
    };

    if (value & 0x0100) > 0 {
        strings.push(String::from("Start ADC conversion"));
    }

    if (value & 0x0200) > 0 {
        strings.push(String::from("Wait for previous conversion to be read before starting next one"));
    }

    if (value & 0x0400) > 0 {
        strings.push(String::from("Channel injection mode"));
    }

    if (value & 0x0600) > 0 {
        strings.push(String::from("Channel injection request"));
    }

    let ctc = value & 0xC000;
    let stc = value & 0x3000;

    let ctc_mult = match ctc {
        0x00 => 24,
        0x02 => 96,
        0x03 => 48,
        _ => -1
    };

    let stc_mult = match stc {
        0x00 => 1,
        0x01 => 2,
        0x02 => 4,
        0x03 => 8,
        _ => -1
    };

    if ctc_mult != -1 {
        // TCL = 2x CPU freq
        strings.push(format!("Conversion clock (Tcc) = TCL * {}", ctc_mult));
        strings.push(format!("Sample clock (Tsc) = Tcc * {}", stc_mult));
        let a = 14 * ctc_mult;
        let b = 2 * a * stc_mult;
        let c = 4;
        strings.push(format!("Conversion time = {} TCL?", a+b+c));
    }

    strings.join("\n")
}

fn annotate_sfr_immed(an: *mut RAnal, pc: u64, values: &InstructionArguments) {
    let value : u16 = values.data.unwrap();
    let mut strings : Vec<String> = Vec::new();

    let sfr : SpecialFunctionRegister  = SpecialFunctionRegister::from_int(values.register0.unwrap());

    match sfr {
        SpecialFunctionRegister::ADCON => {
            strings.push(format_adcon(value));
        },
        SpecialFunctionRegister::ADDRSEL1 |
        SpecialFunctionRegister::ADDRSEL2 |
        SpecialFunctionRegister::ADDRSEL3 |
        SpecialFunctionRegister::ADDRSEL4 => {
        },
        SpecialFunctionRegister::DPP0 |
        SpecialFunctionRegister::DPP1 |
        SpecialFunctionRegister::DPP2 |
        SpecialFunctionRegister::DPP3 => {
            strings.push(format!("Assume {} = {:04X}h", sfr.to_string(), value as u32 * 0x4000));
        },
        SpecialFunctionRegister::S0BG => {
            eprintln!("Trying to annotate S0BG at {:X}", pc);
            strings.push(format_s0bg(value))
        },
        SpecialFunctionRegister::S0CON => {
            strings.push(format_s0con(value))
        },
        SpecialFunctionRegister::WDTCON => {
            match value & 0x01 {
                1 => strings.push(String::from("WDTIN = Watchdog frequency 10Mhz")),
                _ => strings.push(String::from("WDTIN = Watchdog frequency 156.25Khz"))
            }

            strings.push(format!("WDTREL = Initial timer value 0x{:04X}", value & 0xFF00));
        }
        _ => {}
    }

    if !strings.is_empty() {
        add_comments_at_address(an, pc, &strings);
    }
}

pub fn annotate_sfr_ops(op: &Instruction, values: &InstructionArguments, an: *mut RAnal, pc: u64) {
    let op_flags : u32 = op.r2_op_type.uint_value();
    let op_type : _RAnalOpType = _RAnalOpType(0x000000FF & op_flags);

    match op_type {
        _RAnalOpType::R_ANAL_OP_TYPE_MOV => {
            if op.dst_type.intersects(InstructionParameterType::SPECIAL_REGISTER) &&
            op.dst_param == InstructionParameter::Register0 &&
            op.src_type.intersects(InstructionParameterType::IMMEDIATE) {
                annotate_sfr_immed(an, pc, &values);
            }
        },
        _ => {}
    }
}

