use std::{fs, path::Path};

use anyhow::Result;
use ark_serialize::CanonicalDeserialize;
use liminal_ark_relations::{
    environment::{CircuitField, Groth16, ProvingSystem},
    serialization::serialize,
    ConstraintSynthesizer,
};

pub type DepositId = u16;

pub type LeafIdx = u32;

pub const MERKLE_PATH_MAX_LEN: u8 = 16;
<<<<<<< HEAD
pub const VOTE_BASES: [[u8; 48]; 4] = [
    [
        131, 243, 22, 251, 27, 15, 154, 154, 252, 137, 52, 42, 231, 183, 121, 207, 68, 95, 68, 69,
        244, 238, 227, 27, 58, 108, 44, 150, 223, 140, 129, 232, 31, 152, 214, 153, 240, 95, 130,
        13, 132, 10, 101, 131, 236, 124, 12, 44,
    ],
    [
        153, 79, 94, 143, 147, 208, 228, 13, 192, 64, 24, 57, 66, 193, 85, 11, 195, 75, 28, 217,
        165, 46, 233, 4, 104, 89, 98, 228, 229, 161, 118, 59, 199, 47, 89, 93, 60, 84, 126, 107,
        97, 183, 40, 255, 177, 20, 52, 140,
    ],
    [
        170, 102, 22, 74, 123, 164, 5, 124, 121, 139, 107, 175, 157, 91, 212, 41, 60, 183, 33, 138,
        222, 56, 117, 34, 45, 87, 244, 111, 197, 10, 199, 246, 122, 78, 75, 81, 145, 211, 131, 106,
        162, 251, 14, 168, 47, 119, 102, 169,
    ],
    [
        178, 43, 151, 216, 24, 165, 67, 133, 253, 118, 49, 69, 225, 146, 160, 252, 192, 121, 8,
        170, 211, 191, 186, 248, 70, 255, 103, 115, 159, 176, 219, 76, 86, 143, 188, 54, 131, 49,
        236, 214, 72, 12, 34, 69, 66, 151, 223, 11,
    ],
];
=======
pub const VOTE_BASES: [[u64; 4]; 2] = [[2, 0, 0, 0], [3, 0, 0, 0]];
>>>>>>> 2fb01f68235bee2c2fad8769cc8239665862ad4b

pub mod app_state;
pub mod contract;
pub mod deposit;
pub mod ink_contract;
pub mod merge;
pub mod vote;
pub mod withdraw;

/// Generates a Groth16 proof for the given `circuit` using proving key from the file.
/// Returns an error when either reading file or deserialization of the proving key fails.
pub fn generate_proof(
    circuit: impl ConstraintSynthesizer<CircuitField>,
    proving_key_file: &Path,
) -> Result<Vec<u8>> {
    let pk_bytes = fs::read(proving_key_file)?;
    let pk = <<Groth16 as ProvingSystem>::ProvingKey>::deserialize_compressed(&*pk_bytes)?;

    Ok(serialize(&Groth16::prove(&pk, circuit)))
}
