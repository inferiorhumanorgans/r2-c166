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
fn op_c0() {
    test_disasm_op!([0xC0, 0x44], "movbz r4, rl2");
}

#[test]
fn op_c2() {
    test_disasm_op!([0xC2, 0x06, 0x10, 0x01], "movbz MDH, 0110h");
}

#[test]
fn op_c2_fuzz() {
    for addr in 0x00..=0xFF {
        test_disasm_op_no_panic!([0xC2, addr as u8, 0x25, 0x42]);
    }
}

#[test]
fn op_c5() {
    test_disasm_op!([0xC5, 0x06, 0x10, 0x01], "movbz 0110h, MDH");
}

#[test]
fn op_c5_fuzz() {
    for addr in 0x00..=0xFF {
        test_disasm_op_no_panic!([0xC5, addr as u8, 0x25, 0x42]);
    }
}
