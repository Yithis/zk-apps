use std::path::Path;

use aleph_client::SignedConnection;
use anyhow::Result;
<<<<<<< HEAD
use ark_ff::field_hashers::HashToField;
use liminal_ark_relations::shielder::{
    types::{FrontendEncryptedVote, FrontendVote, FrontendVoteRandomness},
=======
use liminal_ark_relations::shielder::{
    types::{FrontendEncryptedVote, FrontendTokenAmount, FrontendVote, FrontendVoteRandomness},
>>>>>>> 2fb01f68235bee2c2fad8769cc8239665862ad4b
    VoteRelationWithFullInput,
};

use crate::{
    app_state::{AppState, Deposit},
    contract::Shielder,
    generate_proof, MERKLE_PATH_MAX_LEN, VOTE_BASES,
};

pub async fn vote(
    contract: &Shielder,
    connection: &SignedConnection,
    deposit: Deposit,
    first_vote_hash: FrontendEncryptedVote,
    second_vote_hash: FrontendEncryptedVote,
<<<<<<< HEAD
    encrypted_x_r: [u8; 48],
    encrypted_first_vote: [u8; 48],
    encrypted_second_vote: [u8; 48],
=======
>>>>>>> 2fb01f68235bee2c2fad8769cc8239665862ad4b
    first_vote: FrontendVote,
    second_vote: FrontendVote,
    vote_randomness: FrontendVoteRandomness,
    proving_key_file: &Path,
    app_state: &mut AppState,
) -> Result<()> {
    let Deposit {
        token_id,
        token_amount,
        trapdoor,
        nullifier,
        leaf_idx,
        note,
        ..
    } = deposit;

    let merkle_root = contract.get_merkle_root(connection).await;
    let merkle_path = contract
        .get_merkle_path(connection, leaf_idx)
        .await
        .expect("Path does not exist");

    let circuit = VoteRelationWithFullInput::new(
        MERKLE_PATH_MAX_LEN,
        VOTE_BASES.into(),
        token_id,
        nullifier,
        token_amount,
        first_vote_hash,
        second_vote_hash,
        merkle_root,
        trapdoor,
        first_vote,
        second_vote,
        vote_randomness,
        merkle_path,
        leaf_idx.into(),
        note,
    );
    let proof = generate_proof(circuit, proving_key_file)?;

    let _leaf_idx = contract
        .vote(
            connection,
            token_id,
            nullifier,
            token_amount,
<<<<<<< HEAD
            encrypted_x_r,
            encrypted_first_vote,
            encrypted_second_vote,
=======
            encrypted_vote,
>>>>>>> 2fb01f68235bee2c2fad8769cc8239665862ad4b
            merkle_root,
            &proof,
        )
        .await?;

    app_state.delete_deposit_by_id(deposit.deposit_id);

    Ok(())
}
