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
fn op_d0() {
    test_asm_op!("movbs r4, rl2", [0xD0, 0x44]);
}

#[test]
fn op_d2() {
    test_asm_op!("movbs MDH, 0110h", [0xD2, 0x06, 0x10, 0x01]);
}

#[test]
fn op_d5() {
    test_asm_op!("movbs 0110h, MDH", [0xD5, 0x06, 0x10, 0x01]);
}
