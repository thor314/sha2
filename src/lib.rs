//! Let's write sha2!
//! Things to know:
//! There are 6 algs spec'd in the standard: 224, 256, 512_224, 512_256, 384, and 512.
//!
//! really, there are only 2 core algorithms, 256 and 512. The rest are these with different initial hash values, truncated to digest lengths.
//!

#[cfg(test)]
mod tests {
    use std::result;

    use super::*;
    use hex_literal::hex;
    #[test]
    fn test_256_512() {
        let mut hasher = Sha256::new();
        hasher.update(b"hello world");
        let result = hasher.finalize();
        // assert_eq!(result, hex!("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"));

        // let mut hasher = Sha512::new();}
        // hasher.update(b"hello world");
        // let result = hasher.finalize();
        // assert_eq!(result,hex!("309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f
        // 989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f
        // "));
    }
}
// todo: no_std
// todo: configure docs

// pub use digest::{self, Digest};
// use digest::{
//     consts::{U28, U32, U48, U64},
//     core_apyi::{CoreWrapper, CtVariableCoreWrapper},
// };

mod consts;
mod core_api;
mod sha256;
// mod sha512

// #[cfg(feature="compress")]
// pub use sha256::compress256;

// #[cfg(feature = "compress")]
// pub use sha512::compress512;

// pub use core_api::{Sha256VarCore, Sha512VarCore};

// /// SHA-224 hasher.
// pub type Sha224 = CoreWrapper<CtVariableCoreWrapper<Sha256VarCore, U28>>;
// /// SHA-256 hasher.
// pub type Sha256 = CoreWrapper<CtVariableCoreWrapper<Sha256VarCore, U32>>;
// /// SHA-512/224 hasher.
// pub type Sha512_224 = CoreWrapper<CtVariableCoreWrapper<Sha512VarCore, U28>>;
// /// SHA-512/256 hasher.
// pub type Sha512_256 = CoreWrapper<CtVariableCoreWrapper<Sha512VarCore, U32>>;
// /// SHA-384 hasher.
// pub type Sha384 = CoreWrapper<CtVariableCoreWrapper<Sha512VarCore, U48>>;
// /// SHA-512 hasher.
// pub type Sha512 = CoreWrapper<CtVariableCoreWrapper<Sha512VarCore, U64>>;

