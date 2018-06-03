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
fn op_f0() {
    test_asm_op!("mov r5, r4", [0xF0, 0x54]);
}

#[test]
fn op_e0() {
    test_asm_op!("mov r5, #04h", [0xE0, 0x45]);
}

#[test]
fn op_e6() {
    test_asm_op!("mov PWMCON0, #4224h", [0xE6, 0x98, 0x24, 0x42]);
}

#[test]
fn op_a8() {
    test_asm_op!("mov r5, [r4]", [0xA8, 0x54]);
}

#[test]
fn op_98() {
    test_asm_op!("mov r5, [r4+]", [0x98, 0x54]);
}

#[test]
fn op_b8() {
    test_asm_op!("mov [r4], r5", [0xB8, 0x54]);
}

#[test]
fn op_88() {
    test_asm_op!("mov [-r4], r5", [0x88, 0x54]);
}

#[test]
fn op_c8() {
    test_asm_op!("mov [r5], [r4]", [0xC8, 0x54]);
}

#[test]
fn op_d8() {
    test_asm_op!("mov [r5+], [r4]", [0xD8, 0x54]);
}

#[test]
fn op_e8() {
    test_asm_op!("mov [r5], [r4+]", [0xE8, 0x54]);
}

#[test]
fn op_d4() {
    test_asm_op!("mov r9, [r8 + #4224h]", [0xD4, 0x98, 0x24, 0x42]);
}

#[test]
fn op_c4() {
    test_asm_op!("mov [r8 + #4224h], r9", [0xC4, 0x98, 0x24, 0x42]);
}

#[test]
fn op_84_1() {
    test_asm_op!("mov [r8], 4224h", [0x84, 0x08, 0x24, 0x42]);
}

#[test]
fn op_94_1() {
    test_asm_op!("mov 4224h, [r8]", [0x94, 0x08, 0x24, 0x42]);
}


#[test]
fn op_f2() {
    test_asm_op!("mov PWMCON0, 4224h", [0xF2, 0x98, 0x24, 0x42]);
}

#[test]
fn op_f6() {
    test_asm_op!("mov 4224h, PWMCON0", [0xF6, 0x98, 0x24, 0x42]);
}
