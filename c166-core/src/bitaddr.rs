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

use ::instruction::*;
use ::reg::*;

pub fn bitoff_to_string(offset: u8, is_ext : bool) -> Result<String, String> {
    match offset {
        0x00...0x7F => {
            // RAM
            Ok(format!("{:04X}h", 0xFD00 + ((2 * offset) as u16)))
        },
        0x80...0xEF => {
            // Special fn registers
            match is_ext {
                false => {
                    // SFR
                    let address : u16 = 0xFF00 + (2 * (offset & 0b01111111)) as u16;
                    match Reg::from_phys16(address, &OperandType::WordRegister(0)) {
                        Ok(reg) => Ok(format!("{}", reg)),
                        Err(_) => Err(format!("No reg found at {:04X}h", address))
                    }
                },
                true => {
                    // 'reg' accesses to the ESFR area require a preceding EXT*R instruction to switch the base address
                    // not available in the SAB 8XC166(W) devices
                    // ESFR
                    let address = 0xF100 + ((2 * (offset & 0b01111111)) as u16);
                    Ok(format!("{:04X}", address))
                }
            }
        },
        0xF0...0xFF => {
            let reg = Reg::from_reg8(offset, &OperandType::WordRegister(0)).unwrap();
            Ok(format!("{}", reg))
        },
        _ => {
            Err(format!("Invalid bit offset {:X}", offset))
        }
    }
}
