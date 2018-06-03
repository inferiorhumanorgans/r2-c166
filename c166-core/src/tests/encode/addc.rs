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
fn op_10() {
    test_asm_op!("addc r4, r4", [0x10, 0x44]);
}

#[test]
fn op_18_1() {
    test_asm_op!("addc r4, [r3]", [0x18, (0x04 << 4) | (0b10 << 2) | 0x03]);
}

#[test]
fn op_18_2() {
    test_asm_op!("addc r4, [r3+]", [0x18, (0x04 << 4) | (0b11 << 2) | 0x03]);
}

#[test]
fn op_18_3() {
    test_asm_op!("addc r4, #04h", [0x18, (0x04 << 4) | (0b00 << 2) | 0x04]);
}

#[test]
fn op_16() {
    test_asm_op!("addc DPP3, #7856h", [0x16, 0x03, 0x56, 0x78]);
}

#[test]
fn op_12() {
    test_asm_op!("addc DPP3, 7856h", [0x12, 0x03, 0x56, 0x78]);
}

#[test]
fn op_14() {
    test_asm_op!("addc 7856h, DPP3", [0x14, 0x03, 0x56, 0x78]);
}

