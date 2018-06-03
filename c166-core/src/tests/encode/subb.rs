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

test_requires_encode!();

#[test]
fn op_21() {
    test_asm_op!("subb rh1, rl3", [0x21, (0x03 << 4) | 0x06]);
}

#[test]
fn op_29_1() {
    test_asm_op!("subb rh1, [r3]", [0x29, (0x03 << 4) | (0b10 << 2) | 0x03]);
}

#[test]
fn op_29_2() {
    test_asm_op!("subb rh1, [r3+]", [0x29, (0x03 << 4) | (0b11 << 2) | 0x03]);
}

#[test]
fn op_29_3() {
    test_asm_op!("subb rh1, #05h", [0x29, (0x03 << 4) | (0b00 << 2) | 0x05]);
}

#[test]
fn op_27() {
    test_asm_op!("subb ADDRSEL1, #FFh", [0x27, 0x0C, 0xFF, 0x42]);
}

#[test]
fn op_23() {
    test_asm_op!("subb rl6, CCFFh", [0x23, 0xFC, 0xFF, 0xCC]);
}

#[test]
fn op_25() {
    test_asm_op!("subb CCFFh, rl6", [0x25, 0xFC, 0xFF, 0xCC]);
}
