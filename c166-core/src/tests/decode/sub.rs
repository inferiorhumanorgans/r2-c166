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
fn op_20() {
    test_disasm_op!([0x20, (0x03 << 4) | 0x06], "sub r3, r6");
}

#[test]
fn op_28_1() {
    test_disasm_op!([0x28, (0x03 << 4) | (0b10 << 2) | 0x03], "sub r3, [r3]");
}

#[test]
fn op_28_2() {
    test_disasm_op!([0x28, (0x03 << 4) | (0b11 << 2) | 0x03], "sub r3, [r3+]");
}

#[test]
fn op_28_3() {
    test_disasm_op!([0x28, (0x03 << 4) | (0b00 << 2) | 0x05], "sub r3, #05h");
}

#[test]
fn op_26() {
    test_disasm_op!([0x26, 0xF4, 0xFF, 0xCC], "sub r4, #CCFFh");
}

#[test]
fn op_26_fuzz() {
    for addr in 0x00..=0xFF {
        test_disasm_op_no_panic!([0x26, addr as u8, 0x25, 0x42]);
    }
}

#[test]
fn op_22() {
    test_disasm_op!([0x22, 0xF4, 0xFF, 0xCC], "sub r4, CCFFh");
}

#[test]
fn op_22_fuzz() {
    for addr in 0x00..=0xFF {
        test_disasm_op_no_panic!([0x22, addr as u8, 0x25, 0x42]);
    }
}

#[test]
fn op_24() {
    test_disasm_op!([0x24, 0xF4, 0xFF, 0xCC], "sub CCFFh, r4");
}

#[test]
fn op_24_fuzz() {
    for addr in 0x00..=0xFF {
        test_disasm_op_no_panic!([0x24, addr as u8, 0x25, 0x42]);
    }
}
