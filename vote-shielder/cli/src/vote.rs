use std::path::Path;

use aleph_client::SignedConnection;
use anyhow::Result;
use liminal_ark_relations::shielder::{
    types::{FrontendEncryptedVote, FrontendTokenAmount, FrontendVote, FrontendVoteRandomness},
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
            encrypted_vote,
            merkle_root,
            &proof,
        )
        .await?;

    app_state.delete_deposit_by_id(deposit.deposit_id);

    Ok(())
}
