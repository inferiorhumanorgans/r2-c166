extern crate byteorder;

pub mod encoding;
pub mod instruction;
pub mod opformat;
pub mod r2;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
