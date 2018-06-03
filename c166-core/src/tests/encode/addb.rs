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
fn op_01() {
    test_asm_op!("addb rl2, rl2", [0x01, 0x44]);
}

#[test]
fn op_09_1() {
    test_asm_op!("addb rl2, [r3]", [0x09, (0x04 << 4) | (0b10 << 2) | 0x03]);
}

#[test]
fn op_09_2() {
    test_asm_op!("addb rl2, [r3+]", [0x09, (0x04 << 4) | (0b11 << 2) | 0x03]);
}

#[test]
fn op_09_3() {
    test_asm_op!("addb rl2, #04h", [0x09, (0x04 << 4) | (0b00 << 2) | 0x04]);
}

#[test]
fn op_07() {
    test_asm_op!("addb DPP3, #56h", [0x07, 0x03, 0x56, 0x42]);
}

#[test]
fn op_03() {
    test_asm_op!("addb DPP3, 7856h", [0x03, 0x03, 0x56, 0x78]);
}

#[test]
fn op_05() {
    test_asm_op!("addb 7856h, DPP3", [0x05, 0x03, 0x56, 0x78]);
}

