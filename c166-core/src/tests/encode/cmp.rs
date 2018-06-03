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
fn op_40() {
    test_asm_op!("cmp r4, r4", [0x40, 0x44]);
}

#[test]
fn op_48_1() {
    test_asm_op!("cmp r4, [r3]", [0x48, (0x04 << 4) | (0b10 << 2) | 0x03]);
}

#[test]
fn op_48_2() {
    test_asm_op!("cmp r4, [r3+]", [0x48, (0x04 << 4) | (0b11 << 2) | 0x03]);
}

#[test]
fn op_48_3() {
    test_asm_op!("cmp r4, #04h", [0x48, (0x04 << 4) | (0b00 << 2) | 0x04]);
}

#[test]
fn op_46() {
    test_asm_op!("cmp DPP3, #7856h", [0x46, 0x03, 0x56, 0x78]);
}

#[test]
fn op_42() {
    test_asm_op!("cmp DPP3, 7856h", [0x42, 0x03, 0x56, 0x78]);
}

