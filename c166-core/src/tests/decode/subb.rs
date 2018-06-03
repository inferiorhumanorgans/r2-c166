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
fn op_21() {
    test_disasm_op!([0x21, (0x03 << 4) | 0x06], "subb rh1, rl3");
}

#[test]
fn op_29_1() {
    test_disasm_op!([0x29, (0x03 << 4) | (0b10 << 2) | 0x03], "subb rh1, [r3]");
}

#[test]
fn op_29_2() {
    test_disasm_op!([0x29, (0x03 << 4) | (0b11 << 2) | 0x03], "subb rh1, [r3+]");
}

#[test]
fn op_29_3() {
    test_disasm_op!([0x29, (0x03 << 4) | (0b00 << 2) | 0x05], "subb rh1, #05h");
}

#[test]
fn op_27() {
    test_disasm_op!([0x27, 0x0C, 0xFF, 0xCC], "subb ADDRSEL1, #FFh");
}

#[test]
fn op_27_fuzz() {
    for addr in 0x00..=0xFF {
        test_disasm_op_no_panic!([0x27, addr as u8, 0x25, 0x42]);
    }
}

#[test]
fn op_23() {
    test_disasm_op!([0x23, 0xFC, 0xFF, 0xCC], "subb rl6, CCFFh");
}

#[test]
fn op_23_fuzz() {
    for addr in 0x00..=0xFF {
        test_disasm_op_no_panic!([0x23, addr as u8, 0x25, 0x42]);
    }
}

#[test]
fn op_25() {
    test_disasm_op!([0x25, 0xFC, 0xFF, 0xCC], "subb CCFFh, rl6");
}

#[test]
fn op_25_fuzz() {
    for addr in 0x00..=0xFF {
        test_disasm_op_no_panic!([0x25, addr as u8, 0x25, 0x42]);
    }
}
