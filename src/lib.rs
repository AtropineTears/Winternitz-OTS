extern crate getrandom;
extern crate blake2_rfc;
extern crate hex;

mod wots;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
