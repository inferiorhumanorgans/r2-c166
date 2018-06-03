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

test_requires_decode!();

#[test]
fn op_50() {
    test_disasm_op!([0x50, 0x08], "xor r0, r8");
}

#[test]
fn op_58_1() {
    test_disasm_op!([0x58, (0x02 << 4) | (0b10 << 2) | 0x03], "xor r2, [r3]");
}

#[test]
fn op_58_2() {
    test_disasm_op!([0x58, (0x02 << 4) | (0b11 << 2) | 0x03], "xor r2, [r3+]");
}

#[test]
fn op_58_3() {
    test_disasm_op!([0x58, (0x02 << 4) | (0b00 << 2) | 0x03], "xor r2, #03h");
}

#[test]
fn op_56_1() {
    test_disasm_op!([0x56, 0xF8, 0x25, 0x42], "xor r8, #4225h");
}

#[test]
fn op_56_2() {
    test_disasm_op!([0x56, 0xFF, 0x25, 0x42], "xor r15, #4225h");
}

#[test]
fn op_56_fuzz() {
    for addr in 0x00..=0xFF {
        test_disasm_op_no_panic!([0x56, addr as u8, 0x25, 0x42]);
    }
}

#[test]
fn op_52_1() {
    test_disasm_op!([0x52, 0xF8, 0x25, 0x42], "xor r8, 4225h");
}

#[test]
fn op_52_2() {
    test_disasm_op!([0x52, 0x06, 0x25, 0x42], "xor MDH, 4225h");
}

#[test]
fn op_52_fuzz() {
    for addr in 0x00..=0xFF {
        test_disasm_op_no_panic!([0x52, addr as u8, 0x25, 0x42]);
    }
}

#[test]
fn op_54_1() {
    test_disasm_op!([0x54, 0xF4, 0x25, 0x42], "xor 4225h, r4");
}

#[test]
fn op_54_2() {
    test_disasm_op!([0x54, 0xF4, 0x25, 0x42], "xor 4225h, r4");
}

#[test]
fn op_54_fuzz() {
    for addr in 0x00..=0xFF {
        test_disasm_op_no_panic!([0x54, addr as u8, 0x25, 0x42]);
    }
}
