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
fn op_20() {
    test_asm_op!("sub r3, r6", [0x20, (0x03 << 4) | 0x06]);
}

#[test]
fn op_28_1() {
    test_asm_op!("sub r3, [r3]", [0x28, (0x03 << 4) | (0b10 << 2) | 0x03]);
}

#[test]
fn op_28_2() {
    test_asm_op!("sub r3, [r3+]", [0x28, (0x03 << 4) | (0b11 << 2) | 0x03]);
}

#[test]
fn op_28_3() {
    test_asm_op!("sub r3, #05h", [0x28, (0x03 << 4) | (0b00 << 2) | 0x05]);
}

#[test]
fn op_26() {
    test_asm_op!("sub r4, #CCFFh", [0x26, 0xF4, 0xFF, 0xCC]);
}

#[test]
fn op_22() {
    test_asm_op!("sub r4, CCFFh", [0x22, 0xF4, 0xFF, 0xCC]);
}

#[test]
fn op_24() {
    test_asm_op!("sub CCFFh, r4", [0x24, 0xF4, 0xFF, 0xCC]);
}
