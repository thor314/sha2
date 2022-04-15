use core::fmt;
use std::slice::from_ref;

use crate::consts;
use crate::sha256::compress256;
use digest::block_buffer::Eager;
use digest::core_api::{Block, Buffer, BufferKindUser, TruncSide, UpdateCore, VariableOutputCore, AlgorithmName};
use digest::typenum::{Unsigned, U32, U64};
use digest::{core_api::BlockSizeUser, HashMarker, Output};
use digest::{InvalidOutputSize, OutputSizeUser};

// Noted: Every method in the impl is a trait impl. All of these hash methods are standard, and implemented as such.

#[derive(Clone)]
pub struct Sha256VarCore {
    state: consts::State256,
    block_len: u64,
}

/// Marker trait for cryptographic hash functions
impl HashMarker for Sha256VarCore {}
/// processes data in blocks of size BlockSize
/// Qn: why U64?
impl BlockSizeUser for Sha256VarCore {
    type BlockSize = U64;
}

/// Eager block buffer kind, which guarantees that buffer position
/// always lies in the range of `0..BlockSize`.
/// As opposed to Lazy.
impl BufferKindUser for Sha256VarCore {
    type BufferKind = Eager;
}

impl UpdateCore for Sha256VarCore {
    // Qn: Why inline here?
    #[inline]
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        // note: blocklen came from BlockSizeUser
        self.block_len += blocks.len() as u64;
        compress256(&mut self.state, blocks);
    }
}

/// Types which return data with the given size.
impl OutputSizeUser for Sha256VarCore {
    // qn: why u32?
    type OutputSize = U32;
}

impl VariableOutputCore for Sha256VarCore {
    /// Truncate left side, i.e. `&out[..n]`.
    const TRUNC_SIDE: TruncSide = TruncSide::Left;

    #[inline]
    fn new(output_size: usize) -> Result<Self, digest::InvalidOutputSize> {
        let state = match output_size {
            28 => consts::H256_224,
            32 => consts::H256_256,
            _ => return Err(InvalidOutputSize),
        };
        // huh, init block len is 0
        let block_len = 0;
        Ok(Self { state, block_len })
    }

    #[inline]
    fn finalize_variable_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
        // bs is initally 64, interestin
        let bs = Self::BlockSize::U64;
        // I guess
        let bit_len = 8 * (buffer.get_pos() as u64 + bs * self.block_len);
        buffer.len64_padding_be(bit_len, |b| compress256(&mut self.state, from_ref(b)));

        for (chunk, v) in out.chunks_exact_mut(4).zip(self.state.iter()) {
            chunk.copy_from_slice(&v.to_be_bytes());
        }
    }
}

impl AlgorithmName for Sha256VarCore{
    #[inline]
    fn write_alg_name(f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Sha256")
    }
}

impl fmt::Debug for Sha256VarCore{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Sha256VarCore { ... }")
    }
}
