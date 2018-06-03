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
fn op_30() {
    test_asm_op!("subc r3, r6", [0x30, (0x03 << 4) | 0x06]);
}

#[test]
fn op_38_1() {
    test_asm_op!("subc r3, [r3]", [0x38, (0x03 << 4) | (0b10 << 2) | 0x03]);
}

#[test]
fn op_38_2() {
    test_asm_op!("subc r3, [r3+]", [0x38, (0x03 << 4) | (0b11 << 2) | 0x03]);
}

#[test]
fn op_38_3() {
    test_asm_op!("subc r3, #05h", [0x38, (0x03 << 4) | (0b00 << 2) | 0x05]);
}

#[test]
fn op_36() {
    test_asm_op!("subc r12, #CCFFh", [0x36, 0xFC, 0xFF, 0xCC]);
}

#[test]
fn op_32() {
    test_asm_op!("subc r12, CCFFh", [0x32, 0xFC, 0xFF, 0xCC]);
}

#[test]
fn op_34() {
    test_asm_op!("subc CCFFh, r12", [0x34, 0xFC, 0xFF, 0xCC]);
}
