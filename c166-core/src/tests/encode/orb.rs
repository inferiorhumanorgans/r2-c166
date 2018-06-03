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
fn op_71() {
    test_asm_op!("orb rh1, rl4", [0x71, 0x38]);
}

#[test]
fn op_79_1() {
    test_asm_op!("orb rl4, [r2]", [0x79, (0x08 << 4) | (0b10 << 2) | 0x02]);
}

#[test]
fn op_79_2() {
    test_asm_op!("orb rl4, [r2+]", [0x79, (0x08 << 4) | (0b11 << 2) | 0x02]);
}

#[test]
fn op_79_3() {
    test_asm_op!("orb rl4, #02h", [0x79, (0x08 << 4) | (0b00 << 2) | 0x02]);
}

#[test]
fn op_77() {
    test_asm_op!("orb ZEROS, #88h", [0x77, 0x8E, 0x88, 0x42]);
}

#[test]
fn op_73() {
    test_asm_op!("orb ZEROS, 5588h", [0x73, 0x8E, 0x88, 0x55]);
}


#[test]
fn op_75() {
    test_asm_op!("orb 5588h, ZEROS", [0x75, 0x8E, 0x88, 0x55]);
}
