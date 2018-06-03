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
fn op_0e() {
    test_asm_op!("bclr P8.0", [0x0E, 0xEA]);
}

#[test]
fn op_1e() {
    test_asm_op!("bclr P8.1", [0x1E, 0xEA]);
}

#[test]
fn op_2e() {
    test_asm_op!("bclr P8.2", [0x2E, 0xEA]);
}

#[test]
fn op_3e() {
    test_asm_op!("bclr P8.3", [0x3E, 0xEA]);
}

#[test]
fn op_4e() {
    test_asm_op!("bclr P8.4", [0x4E, 0xEA]);
}

#[test]
fn op_5e() {
    test_asm_op!("bclr P8.5", [0x5E, 0xEA]);
}

#[test]
fn op_6e() {
    test_asm_op!("bclr P8.6", [0x6E, 0xEA]);
}

#[test]
fn op_7e() {
    test_asm_op!("bclr P8.7", [0x7E, 0xEA]);
}
