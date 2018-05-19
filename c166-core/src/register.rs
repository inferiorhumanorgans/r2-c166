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

pub fn get_sfr_register_mnem(register: u32) -> Option<&'static str> {
    if register > <u8>::max_value() as u32 {
        panic!("Register shouldn't be over 8 bits, but is actually {}", register);
    }

    match register {
        0xCC => Some("ADCIC"),
        0xD0 => Some("ADCON"),
        0x50 => Some("ADDAT"),
        0x0C => Some("ADDRSEL1"),
        0x0D => Some("ADDRSEL2"),
        0x0E => Some("ADDRSEL3"),
        0x0F => Some("ADDRSEL4"),
        0xCD => Some("ADEIC"),
        0x86 => Some("BUSCON0"),
        0x8A => Some("BUSCON1"),
        0x8B => Some("BUSCON2"),
        0x8C => Some("BUSCON3"),
        0x8D => Some("BUSCON4"),
        0x25 => Some("CAPREL"),
        0x40 => Some("CC0"),
        0xBC => Some("CC0IC"),
        0x41 => Some("CC1"),
        0xBD => Some("CC1IC"),
        0x42 => Some("CC2"),
        0xBE => Some("CC2IC"),
        0x43 => Some("CC3"),
        0xBF => Some("CC3IC"),
        0x44 => Some("CC4"),
        0xC0 => Some("CC4IC"),
        0x45 => Some("CC5"),
        0xC1 => Some("CC5IC"),
        0x46 => Some("CC6"),
        0xC2 => Some("CC6IC"),
        0x47 => Some("CC7"),
        0xC3 => Some("CC7IC"),
        0x48 => Some("CC8"),
        0xC4 => Some("CC8IC"),
        0x49 => Some("CC9"),
        0xC5 => Some("CC9IC"),
        0x4A => Some("CC10"),
        0xC6 => Some("CC10IC"),
        0x4B => Some("CC11"),
        0xC7 => Some("CC11IC"),
        0x4C => Some("CC12"),
        0xC8 => Some("CC12IC"),
        0x4D => Some("CC13"),
        0xC9 => Some("CC13IC"),
        0x4E => Some("CC14"),
        0xCA => Some("CC14IC"),
        0x4F => Some("CC15"),
        0xCB => Some("CC15IC"),
        0x30 => Some("CC16"),
        0x31 => Some("CC17"),
        0x32 => Some("CC18"),
        0x33 => Some("CC19"),
        0x34 => Some("CC20"),
        0x35 => Some("CC21"),
        0x36 => Some("CC22"),
        0x37 => Some("CC23"),
        0x38 => Some("CC24"),
        0x39 => Some("CC25"),
        0x3A => Some("CC26"),
        0x3B => Some("CC27"),
        0x3C => Some("CC28"),
        0x3D => Some("CC29"),
        0x3E => Some("CC30"),
        0x3F => Some("CC31"),
        0xA9 => Some("CCM0"),
        0xAA => Some("CCM1"),
        0xAB => Some("CCM2"),
        0xAC => Some("CCM3"),
        0x91 => Some("CCM4"),
        0x92 => Some("CCM5"),
        0x93 => Some("CCM6"),
        0x94 => Some("CCM7"),
        0x08 => Some("CP"),
        0xB5 => Some("CRIC"),
        0x04 => Some("CSP"),
        0xE1 => Some("DP2"),
        0xE3 => Some("DP3"),
        0xE5 => Some("DP4"),
        0xE7 => Some("DP6"),
        0xE9 => Some("DP7"),
        0xEB => Some("DP8"),
        0x00 => Some("DPP0"),
        0x01 => Some("DPP1"),
        0x02 => Some("DPP2"),
        0x03 => Some("DPP3"),
        0x87 => Some("MDC"),
        0x06 => Some("MDH"),
        0x07 => Some("MDL"),
        0x8F => Some("ONES"),
        0x80 => Some("P0L"),
        0x81 => Some("P0H"),
        0x82 => Some("P1L"),
        0x83 => Some("P1H"),
        0xE0 => Some("P2"),
        0xE2 => Some("P3"),
        0xE4 => Some("P4"),
        0xD1 => Some("P5"),
        0xE6 => Some("P6"),
        0xE8 => Some("P7"),
        0xEA => Some("P8"),
        0x60 => Some("PECC0"),
        0x61 => Some("PECC1"),
        0x62 => Some("PECC2"),
        0x63 => Some("PECC3"),
        0x64 => Some("PECC4"),
        0x65 => Some("PECC5"),
        0x66 => Some("PECC6"),
        0x67 => Some("PECC7"),
        0x88 => Some("PSW"),
        0x18 => Some("PW0"),
        0x19 => Some("PW1"),
        0x1A => Some("PW2"),
        0x1B => Some("PW3"),
        0x98 => Some("PWMCON0"),
        0x99 => Some("PWMCON1"),
        0x5A => Some("S0BG"),
        0xD8 => Some("S0CON"),
        0xB8 => Some("S0EIC"),
        0x59 => Some("S0RBUF"),
        0xB7 => Some("S0RIC"),
        0x58 => Some("S0TBUF"),
        0xB6 => Some("S0TIC"),
        0x09 => Some("SP"),
        0xD9 => Some("SSCCON"),
        0xBB => Some("SSCEIC"),
        0xBA => Some("SSCRIC"),
        0xB9 => Some("SSCTIC"),
        0x0A => Some("STKOV"),
        0x0B => Some("STKUN"),
        0x89 => Some("SYSCON"),
        0x28 => Some("T0"),
        0xA8 => Some("T01CON"),
        0xCE => Some("T0IC"),
        0x2A => Some("T0REL"),
        0x29 => Some("T1"),
        0xCF => Some("T1IC"),
        0x2B => Some("T1REL"),
        0x20 => Some("T2"),
        0xA0 => Some("T2CON"),
        0xB0 => Some("T2IC"),
        0x21 => Some("T3"),
        0xA1 => Some("T3CON"),
        0xB1 => Some("T3IC"),
        0x22 => Some("T4"),
        0xA2 => Some("T4CON"),
        0xB2 => Some("T4IC"),
        0x23 => Some("T5"),
        0xA3 => Some("T5CON"),
        0xB3 => Some("T5IC"),
        0x24 => Some("T6"),
        0xA4 => Some("T6CON"),
        0xB4 => Some("T6IC"),
        0x90 => Some("T78CON"),
        0xD6 => Some("TFR"),
        0x57 => Some("WDT"),
        0xD7 => Some("WDTCON"),
        0x8E => Some("ZEROS"),
        _ => None
    }
}

// Get register mnemonic from 8-bit address
// ESFR only
pub fn get_esfr_register_mnem(register: u32) -> Option<&'static str> {
    if register > <u8>::max_value() as u32 {
        panic!("Register shouldn't be over 8 bits, but is actually {}", register);
    }

    match register {
        0x50 => Some("ADDAT2"),
        0xB0 => Some("CC16IC"),
        0xB1 => Some("CC17IC"),
        0xB2 => Some("CC18IC"),
        0xB3 => Some("CC19IC"),
        0xB4 => Some("CC20IC"),
        0xB5 => Some("CC21IC"),
        0xB6 => Some("CC22IC"),
        0xB7 => Some("CC23IC"),
        0xB8 => Some("CC24IC"),
        0xB9 => Some("CC25IC"),
        0xBA => Some("CC26IC"),
        0xBB => Some("CC27IC"),
        0xBC => Some("CC28IC"),
        0xC2 => Some("CC29IC"),
        0xC6 => Some("CC30IC"),
        0xCA => Some("CC31IC"),
        0x80 => Some("DP0L"),
        0x81 => Some("DP0H"),
        0x82 => Some("DP1L"),
        0x83 => Some("DP1H"),
        0xE0 => Some("EXICON"),
        0xE1 => Some("ODP2"),
        0xE3 => Some("ODP3"),
        0xE7 => Some("ODP6"),
        0xE9 => Some("ODP7"),
        0xEB => Some("ODP8"),
        0xE2 => Some("PICON"),
        0x1C => Some("PP0"),
        0x1D => Some("PP1"),
        0x1E => Some("PP2"),
        0x1F => Some("PP3"),
        0x18 => Some("PT0"),
        0x19 => Some("PT1"),
        0x1A => Some("PT2"),
        0x1B => Some("PT3"),
        0xBF => Some("PWMIC"),
        0x84 => Some("RP0H"),
        0xCE => Some("S0TBIC"),
        0x5A => Some("SSCBR"),
        0x59 => Some("SSCRB"),
        0x58 => Some("SSCTB"),
        0x28 => Some("T7"),
        0xBD => Some("T7IC"),
        0x2A => Some("T7REL"),
        0x29 => Some("T8"),
        0xBE => Some("T8IC"),
        0x2B => Some("T8REL"),
        0xC3 => Some("XP0IC"),
        0xC7 => Some("XP1IC"),
        0xCB => Some("XP2IC"),
        0xCF => Some("XP3IC"),
        _ => None
   }
}

pub fn get_register_mnem(register: u32) -> String {
    if register > <u8>::max_value() as u32 {
        panic!("Register shouldn't be over 8 bits, but is actually {}", register);
    }

    match get_sfr_register_mnem(register) {
        Some(mnem) => String::from(mnem),
        None => {
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

pub fn get_byte_register_mnem(register: u32) -> String {
    if register > <u8>::max_value() as u32 {
        panic!("Register shouldn't be over 8 bits, but is actually {}", register);
    }

    match get_sfr_register_mnem(register) {
        Some(mnem) => String::from(mnem),
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

pub fn get_word_gpr_mnem(register: u32) -> String {
    if register > 0x0F as u32 {
        panic!("GPR shouldn't be over 4 bits, but is actually {}", register);
    }

    let reg : u8 = register as u8;
    format!("r{}", reg)
}

pub fn get_byte_gpr_mnem(register: u32) -> String {
    if register > 0x0F as u32 {
        panic!("GPR shouldn't be over 4 bits, but is actually {}", register);
    }

    let reg : u8 = register as u8;

    if (reg & 0b00000001) == 1 {
        format!("rh{}", reg >> 1)
    } else {
        format!("rl{}", reg >> 1)
    }
}

pub fn get_sfr_mnem_from_physical(address: u32) -> Option<&'static str> {
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
