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

use num_traits::{FromPrimitive};
use std::fmt;

#[derive(Debug, Eq, PartialEq, Primitive)]
pub enum SpecialFunctionRegister {
    ADCIC       = 0xCC,
    ADCON       = 0xD0,
    ADDAT       = 0x50,
    ADDRSEL1    = 0x0C,
    ADDRSEL2    = 0x0D,
    ADDRSEL3    = 0x0E,
    ADDRSEL4    = 0x0F,
    ADEIC       = 0xCD,
    BUSCON0     = 0x86,
    BUSCON1     = 0x8A,
    BUSCON2     = 0x8B,
    BUSCON3     = 0x8C,
    BUSCON4     = 0x8D,
    CAPREL      = 0x25,
    CC0         = 0x40,
    CC0IC       = 0xBC,
    CC1         = 0x41,
    CC1IC       = 0xBD,
    CC2         = 0x42,
    CC2IC       = 0xBE,
    CC3         = 0x43,
    CC3IC       = 0xBF,
    CC4         = 0x44,
    CC4IC       = 0xC0,
    CC5         = 0x45,
    CC5IC       = 0xC1,
    CC6         = 0x46,
    CC6IC       = 0xC2,
    CC7         = 0x47,
    CC7IC       = 0xC3,
    CC8         = 0x48,
    CC8IC       = 0xC4,
    CC9         = 0x49,
    CC9IC       = 0xC5,
    CC10        = 0x4A,
    CC10IC      = 0xC6,
    CC11        = 0x4B,
    CC11IC      = 0xC7,
    CC12        = 0x4C,
    CC12IC      = 0xC8,
    CC13        = 0x4D,
    CC13IC      = 0xC9,
    CC14        = 0x4E,
    CC14IC      = 0xCA,
    CC15        = 0x4F,
    CC15IC      = 0xCB,
    CC16        = 0x30,
    CC17        = 0x31,
    CC18        = 0x32,
    CC19        = 0x33,
    CC20        = 0x34,
    CC21        = 0x35,
    CC22        = 0x36,
    CC23        = 0x37,
    CC24        = 0x38,
    CC25        = 0x39,
    CC26        = 0x3A,
    CC27        = 0x3B,
    CC28        = 0x3C,
    CC29        = 0x3D,
    CC30        = 0x3E,
    CC31        = 0x3F,
    CCM0        = 0xA9,
    CCM1        = 0xAA,
    CCM2        = 0xAB,
    CCM3        = 0xAC,
    CCM4        = 0x91,
    CCM5        = 0x92,
    CCM6        = 0x93,
    CCM7        = 0x94,
    CP          = 0x08,
    CRIC        = 0xB5,
    CSP         = 0x04,
    DP2         = 0xE1,
    DP3         = 0xE3,
    DP4         = 0xE5,
    DP6         = 0xE7,
    DP7         = 0xE9,
    DP8         = 0xEB,
    DPP0        = 0x00,
    DPP1        = 0x01,
    DPP2        = 0x02,
    DPP3        = 0x03,
    MDC         = 0x87,
    MDH         = 0x06,
    MDL         = 0x07,
    ONES        = 0x8F,
    P0L         = 0x80,
    P0H         = 0x81,
    P1L         = 0x82,
    P1H         = 0x83,
    P2          = 0xE0,
    P3          = 0xE2,
    P4          = 0xE4,
    P5          = 0xD1,
    P6          = 0xE6,
    P7          = 0xE8,
    P8          = 0xEA,
    PECC0       = 0x60,
    PECC1       = 0x61,
    PECC2       = 0x62,
    PECC3       = 0x63,
    PECC4       = 0x64,
    PECC5       = 0x65,
    PECC6       = 0x66,
    PECC7       = 0x67,
    PSW         = 0x88,
    PW0         = 0x18,
    PW1         = 0x19,
    PW2         = 0x1A,
    PW3         = 0x1B,
    PWMCON0     = 0x98,
    PWMCON1     = 0x99,
    S0BG        = 0x5A,
    S0CON       = 0xD8,
    S0EIC       = 0xB8,
    S0RBUF      = 0x59,
    S0RIC       = 0xB7,
    S0TBUF      = 0x58,
    S0TIC       = 0xB6,
    SP          = 0x09,
    SSCCON      = 0xD9,
    SSCEIC      = 0xBB,
    SSCRIC      = 0xBA,
    SSCTIC      = 0xB9,
    STKOV       = 0x0A,
    STKUN       = 0x0B,
    SYSCON      = 0x89,
    T0          = 0x28,
    T01CON      = 0xA8,
    T0IC        = 0xCE,
    T0REL       = 0x2A,
    T1          = 0x29,
    T1IC        = 0xCF,
    T1REL       = 0x2B,
    T2          = 0x20,
    T2CON       = 0xA0,
    T2IC        = 0xB0,
    T3          = 0x21,
    T3CON       = 0xA1,
    T3IC        = 0xB1,
    T4          = 0x22,
    T4CON       = 0xA2,
    T4IC        = 0xB2,
    T5          = 0x23,
    T5CON       = 0xA3,
    T5IC        = 0xB3,
    T6          = 0x24,
    T6CON       = 0xA4,
    T6IC        = 0xB4,
    T78CON      = 0x90,
    TFR         = 0xD6,
    WDT         = 0x57,
    WDTCON      = 0xD7,
    ZEROS       = 0x8E,
    NONE        = 0xFFFF,
}

impl fmt::Display for SpecialFunctionRegister {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            // Seriously rust??? This is AWFUL.
        	_ => write!(f, "{:?}", self)
        }
    }
}

impl SpecialFunctionRegister {
    pub fn from_int(register: u8) -> SpecialFunctionRegister {
        match SpecialFunctionRegister::from_u8(register) {
            Some(sfr) => sfr,
            _ => SpecialFunctionRegister::NONE
        }
    }
}

pub fn get_sfr_register_mnem(register: u8) -> Option<String> {
    match SpecialFunctionRegister::from_u8(register) {
        Some(sfr) => Some(sfr.to_string()),
        _ => None
    }
}

#[derive(Debug, Eq, PartialEq, Primitive)]
pub enum ExtendedSpecialFunctionRegister {
    ADDAT2  = 0x50,
    CC16IC  = 0xB0,
    CC17IC  = 0xB1,
    CC18IC  = 0xB2,
    CC19IC  = 0xB3,
    CC20IC  = 0xB4,
    CC21IC  = 0xB5,
    CC22IC  = 0xB6,
    CC23IC  = 0xB7,
    CC24IC  = 0xB8,
    CC25IC  = 0xB9,
    CC26IC  = 0xBA,
    CC27IC  = 0xBB,
    CC28IC  = 0xBC,
    CC29IC  = 0xC2,
    CC30IC  = 0xC6,
    CC31IC  = 0xCA,
    DP0L    = 0x80,
    DP0H    = 0x81,
    DP1L    = 0x82,
    DP1H    = 0x83,
    EXICON  = 0xE0,
    ODP2    = 0xE1,
    ODP3    = 0xE3,
    ODP6    = 0xE7,
    ODP7    = 0xE9,
    ODP8    = 0xEB,
    PICON   = 0xE2,
    PP0     = 0x1C,
    PP1     = 0x1D,
    PP2     = 0x1E,
    PP3     = 0x1F,
    PT0     = 0x18,
    PT1     = 0x19,
    PT2     = 0x1A,
    PT3     = 0x1B,
    PWMIC   = 0xBF,
    RP0H    = 0x84,
    S0TBIC  = 0xCE,
    SSCBR   = 0x5A,
    SSCRB   = 0x59,
    SSCTB   = 0x58,
    T7      = 0x28,
    T7IC    = 0xBD,
    T7REL   = 0x2A,
    T8      = 0x29,
    T8IC    = 0xBE,
    T8REL   = 0x2B,
    XP0IC   = 0xC3,
    XP1IC   = 0xC7,
    XP2IC   = 0xCB,
    XP3IC   = 0xCF,
    NONE    = 0xFFFF,
}

impl fmt::Display for ExtendedSpecialFunctionRegister {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            // Seriously rust??? This is AWFUL.
        	_ => write!(f, "{:?}", self)
        }
    }
}

impl ExtendedSpecialFunctionRegister {
    pub fn from_int(register: u8) -> ExtendedSpecialFunctionRegister {
        match ExtendedSpecialFunctionRegister::from_u8(register) {
            Some(sfr) => sfr,
            _ => ExtendedSpecialFunctionRegister::NONE
        }
    }
}

// Get register mnemonic from 8-bit address
// ESFR only
pub fn get_esfr_register_mnem(register: u8) -> Option<String> {
    match ExtendedSpecialFunctionRegister::from_u8(register) {
        Some(esfr) => Some(esfr.to_string()),
        _ => None
    }
}

pub fn get_register_mnem(register: u8, is_byte: bool) -> String {
    match get_sfr_register_mnem(register) {
        Some(mnem) => mnem,
        None => {
            if is_byte {
                match register {
                    0xF0 => String::from("rl0"),
                    0xF1 => String::from("rh0"),
                    0xF2 => String::from("rl1"),
                    0xF3 => String::from("rh1"),
                    0xF4 => String::from("rl2"),
                    0xF5 => String::from("rh2"),
                    0xF6 => String::from("rl3"),
                    0xF7 => String::from("rh3"),
                    0xF8 => String::from("rl4"),
                    0xF9 => String::from("rh4"),
                    0xFA => String::from("rl5"),
                    0xFB => String::from("rh5"),
                    0xFC => String::from("rl6"),
                    0xFD => String::from("rh6"),
                    0xFE => String::from("rl7"),
                    0xFF => String::from("rh7"),
                    _    => format!("{:02}h (reg)", register)
                }
            } else {
                match register {
                    0xF0 => String::from("r0"),
                    0xF1 => String::from("r1"),
                    0xF2 => String::from("r2"),
                    0xF3 => String::from("r3"),
                    0xF4 => String::from("r4"),
                    0xF5 => String::from("r5"),
                    0xF6 => String::from("r6"),
                    0xF7 => String::from("r7"),
                    0xF8 => String::from("r8"),
                    0xF9 => String::from("r9"),
                    0xFA => String::from("r10"),
                    0xFB => String::from("r11"),
                    0xFC => String::from("r12"),
                    0xFD => String::from("r13"),
                    0xFE => String::from("r14"),
                    0xFF => String::from("r15"),
                    _    => format!("{:02}h (reg)", register)
                }
            }
        }
    }
}

pub fn get_byte_register_mnem(register: u8) -> String {
    match get_sfr_register_mnem(register) {
        Some(mnem) => mnem,
        None => {
            match register {
                0xF0 => String::from("rl0"),
                0xF1 => String::from("rh0"),
                0xF2 => String::from("rl1"),
                0xF3 => String::from("rh1"),
                0xF4 => String::from("rl2"),
                0xF5 => String::from("rh2"),
                0xF6 => String::from("rl3"),
                0xF7 => String::from("rh3"),
                0xF8 => String::from("rl4"),
                0xF9 => String::from("rh5"),
                0xFA => String::from("rl5"),
                0xFB => String::from("rh5"),
                0xFC => String::from("rl6"),
                0xFD => String::from("rh6"),
                0xFE => String::from("rl7"),
                0xFF => String::from("rh7"),
                _    => format!("{:02X}h (reg)", register)
            }
        }
    }
}

pub fn get_word_gpr_mnem(register: u8) -> String {
    if register > 0x0F {
        panic!("GPR shouldn't be over 4 bits, but is actually {}", register);
    }

    let reg : u8 = register as u8;
    format!("r{}", reg)
}

pub fn get_byte_gpr_mnem(register: u8) -> String {
    if register > 0x0F {
        panic!("GPR shouldn't be over 4 bits, but is actually {}", register);
    }

    if (register & 0b00000001) == 1 {
        format!("rh{}", register >> 1)
    } else {
        format!("rl{}", register >> 1)
    }
}

pub fn get_sfr_mnem_from_physical(address: u16) -> Option<&'static str> {
    match address {
        0xFF98 => Some("ADCIC"),
        0xFFA0 => Some("ADCON"),
        0xFEA0 => Some("ADDAT"),
        0xF0A0 => Some("ADDAT2"),
        0xFE18 => Some("ADDRSEL1"),
        0xFE1A => Some("ADDRSEL2"),
        0xFE1C => Some("ADDRSEL3"),
        0xFE1E => Some("ADDRSEL4"),
        0xFF9A => Some("ADEIC"),
        0xFF0C => Some("BUSCON0"),
        0xFF14 => Some("BUSCON1"),
        0xFF16 => Some("BUSCON2"),
        0xFF18 => Some("BUSCON3"),
        0xFF1A => Some("BUSCON4"),
        0xEF04 => Some("C1BTR"),
        0xEF00 => Some("C1CSR"),
        0xEF06 => Some("C1GMS"),
        0xEF02 => Some("C1IR"),
        0xEF0A => Some("C1LGML"),
        0xEF0E => Some("C1LMLM"),
        0xEF08 => Some("C1UGML"),
        0xEF0C => Some("C1UMLM"),
        0xFE4A => Some("CAPREL"),
        0xFE80 => Some("CC0"),
        0xFF78 => Some("CC0IC"),
        0xF100 => Some("DP0L"),
        0xF102 => Some("DP1L"),
        0xF106 => Some("DP1H"),
        0xFFC2 => Some("DP2"),
        0xFFC6 => Some("DP3"),
        0xFFCA => Some("DP4"),
        0xFFCE => Some("DP6"),
        0xFFD2 => Some("DP7"),
        0xFFD6 => Some("DP8"),
        0xFE00 => Some("DPP0"),
        0xFE02 => Some("DPP1"),
        0xFE04 => Some("DPP2"),
        0xFE06 => Some("DPP3"),
        0xF1C0 => Some("EXICON"),
        0xFF0E => Some("MDC"),
        0xFE0C => Some("MDH"),
        0xFE0E => Some("MDL"),
        0xF1C2 => Some("ODP2"),
        0xF1C6 => Some("ODP3"),
        0xF1CE => Some("ODP6"),
        0xF1D2 => Some("ODP7"),
        0xF1D6 => Some("ODP8"),
        0xFF1E => Some("ONES"),
        0xFF00 => Some("P0L"),
        0xFF02 => Some("P0H"),
        0xFF04 => Some("P1L"),
        0xFF06 => Some("P1H"),
        0xFFC0 => Some("P2"),
        0xFFC4 => Some("P3"),
        0xFFC8 => Some("P4"),
        0xFFA2 => Some("P5"),
        0xFFCC => Some("P6"),
        0xFFD0 => Some("P7"),
        0xFFD4 => Some("P8"),
        0xFEC0 => Some("PECC0"),
        0xFEC2 => Some("PECC1"),
        0xFEC4 => Some("PECC2"),
        0xFEC6 => Some("PECC3"),
        0xFEC8 => Some("PECC4"),
        0xFECA => Some("PECC5"),
        0xFECC => Some("PECC6"),
        0xFECE => Some("PECC7"),
        0xF1C4 => Some("PICON"),
        0xF038 => Some("PP0"),
        0xF03A => Some("PP1"),
        0xF03C => Some("PP2"),
        0xF03E => Some("PP3"),
        0xFF10 => Some("PSW"),
        0xF030 => Some("PT0"),
        0xF032 => Some("PT1"),
        0xF034 => Some("PT2"),
        0xF036 => Some("PT3"),
        0xFE30 => Some("PW0"),
        0xFE32 => Some("PW1"),
        0xFE34 => Some("PW2"),
        0xFE36 => Some("PW3"),
        0xFF30 => Some("PWMCON0"),
        0xFF32 => Some("PWMCON1"),
        0xF17E => Some("PWMIC"),
        0xF108 => Some("RP0H"),
        0xFEB4 => Some("S0BG"),
        0xFFB0 => Some("S0CON"),
        0xFF70 => Some("S0EIC"),
        0xFEB2 => Some("S0RBUF"),
        0xFF6E => Some("S0RIC"),
        0xF19C => Some("S0TBIC"),
        0xFEB0 => Some("S0TBUF"),
        0xFF6C => Some("S0TIC"),
        0xFE12 => Some("SP"),
        0xF0B4 => Some("SSCBR"),
        0xFFB2 => Some("SSCCON"),
        0xFF76 => Some("SSCEIC"),
        0xF0B2 => Some("SSCRB"),
        0xFF74 => Some("SSCRIC"),
        0xF0B0 => Some("SSCTB"),
        0xFF72 => Some("SSCTIC"),
        0xFE14 => Some("STKOV"),
        0xFE16 => Some("STKUN"),
        0xFF12 => Some("SYSCON"),
        0xFE50 => Some("T0"),
        0xFF50 => Some("T01CON"),
        0xFF9C => Some("T0IC"),
        0xFE54 => Some("T0REL"),
        0xFE52 => Some("T1"),
        0xFF9E => Some("T1IC"),
        0xFE56 => Some("T1REL"),
        0xFFAC => Some("TFR"),
        0xFEAE => Some("WDT"),
        0xFFAE => Some("WDTCON"),
        0xF186 => Some("XP0IC"),
        0xF18E => Some("XP1IC"),
        0xF196 => Some("XP2IC"),
        0xF19E => Some("XP3IC"),
        0xFF1C => Some("ZEROS"),
        _      => None
    }
}
