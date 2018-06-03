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
fn op_dc() {
    test_asm_op!("extp r15, #4", [0xDC, (0b01 << 6) | (0x3 << 4) | 0x0F]);
}

#[test]
fn op_d7_1() {
    test_asm_op!("extp #0020h, #4", [0xD7, (0b01 << 6) | (0x3 << 4) | 0x00, 0x20, 0x00]);
}
