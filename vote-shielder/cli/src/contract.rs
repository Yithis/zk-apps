use std::path::Path;

use aleph_client::{
    contract::{
        event::{get_contract_events, ContractEvent},
        ContractInstance, ConvertibleValue,
    },
    AccountId, AsConnection, Connection, SignedConnection, TxInfo,
};
use anyhow::{anyhow, Result};
use ink_primitives;
use liminal_ark_relations::shielder::types::{
<<<<<<< HEAD
    FrontendMerklePath, FrontendMerkleRoot, FrontendNote, FrontendNullifier, FrontendTokenAmount,
    FrontendTokenId,
=======
    FrontendEncryptedVote, FrontendMerklePath, FrontendMerkleRoot, FrontendNote, FrontendNullifier,
    FrontendTokenAmount, FrontendTokenId,
>>>>>>> 2fb01f68235bee2c2fad8769cc8239665862ad4b
};
use tracing::info;

use crate::ink_contract::Instance;

fn inkify_account_id(account_id: &AccountId) -> ink_primitives::AccountId {
    let inner: [u8; 32] = *account_id.as_ref();
    inner.into()
}

impl From<&ContractInstance> for Instance {
    fn from(contract: &ContractInstance) -> Self {
        let account_id = contract.address();
        let ink_account_id = inkify_account_id(account_id);
        ink_account_id.into()
    }
}

#[derive(Debug)]
pub struct Shielder {
    contract: ContractInstance,
}

impl Shielder {
    pub fn new(address: &AccountId, metadata_path: &Path) -> Result<Self> {
        Ok(Self {
            contract: ContractInstance::new(address.clone(), metadata_path.to_str().unwrap())?,
        })
    }

    /// Call `vote` message of the contract. If successful, return leaf idx.
    #[allow(clippy::too_many_arguments)]
    pub async fn vote(
        &self,
        connection: &SignedConnection,
        token_id: FrontendTokenId,
        nullifier: FrontendNullifier,
        token_amount: FrontendTokenAmount,
<<<<<<< HEAD
        encrypted_x_r: [u8; 48],
        encrypted_first_vote: [u8; 48],
        encrypted_second_vote: [u8; 48],
=======
        encrypted_vote: [u64; 26],
>>>>>>> 2fb01f68235bee2c2fad8769cc8239665862ad4b
        merkle_root: FrontendMerkleRoot,
        proof: &[u8],
    ) -> Result<u32> {
        let ink_contract: Instance = (&self.contract).into();

        let tx_info = ink_contract
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
                proof.to_vec(),
            )
            .await?;

<<<<<<< HEAD
        let _event = self
=======
        let event = self
>>>>>>> 2fb01f68235bee2c2fad8769cc8239665862ad4b
            .get_event(connection.as_connection(), "Voted", tx_info)
            .await?;

        info!("Successfully voted.");
        Ok(0)
    }

    /// Call `deposit` message of the contract. If successful, return leaf idx.
    pub async fn deposit(
        &self,
        connection: &SignedConnection,
        token_id: FrontendTokenId,
        token_amount: FrontendTokenAmount,
        note: FrontendNote,
        proof: &[u8],
    ) -> Result<u32> {
        let ink_contract: Instance = (&self.contract).into();

        let tx_info = ink_contract
            .deposit(connection, token_id, token_amount, note, proof.to_vec())
            .await?;

        let event = self
            .get_event(connection.as_connection(), "Deposited", tx_info)
            .await?;

        Self::extract_leaf_idx_from_event(&event).map(|idx| {
            info!("Successfully deposited tokens.");
            idx
        })
    }

    /// Call `withdraw` message of the contract. If successful, return leaf idx.
    #[allow(clippy::too_many_arguments)]
    pub async fn withdraw(
        &self,
        connection: &SignedConnection,
        token_id: FrontendTokenId,
        value: FrontendTokenAmount,
        recipient: &AccountId,
        fee_for_caller: FrontendTokenAmount,
        merkle_root: FrontendMerkleRoot,
        old_nullifier: FrontendNullifier,
        new_note: FrontendNote,
        proof: &[u8],
    ) -> Result<u32> {
        let ink_contract: Instance = (&self.contract).into();
        let ink_recipient = inkify_account_id(recipient);

        let tx_info = ink_contract
            .withdraw(
                connection,
                token_id,
                value,
                ink_recipient,
                Some(fee_for_caller),
                merkle_root,
                old_nullifier,
                new_note,
                proof.to_vec(),
            )
            .await?;

        let event = self
            .get_event(connection.as_connection(), "Withdrawn", tx_info)
            .await?;

        Self::extract_leaf_idx_from_event(&event).map(|idx| {
            info!("Successfully withdrawn tokens.");
            idx
        })
    }

    /// Call `deposit_and_merge` message of the contract.
    #[allow(clippy::too_many_arguments)]
    pub async fn deposit_and_merge(
        &self,
        connection: &SignedConnection,
        token_id: FrontendTokenId,
        value: FrontendTokenAmount,
        merkle_root: FrontendMerkleRoot,
        old_nullifier: FrontendNullifier,
        new_note: FrontendNote,
        proof: &[u8],
    ) -> Result<u32> {
        let ink_contract: Instance = (&self.contract).into();

        let tx_info = ink_contract
            .deposit_and_merge(
                connection,
                token_id,
                value,
                merkle_root,
                old_nullifier,
                new_note,
                proof.to_vec(),
            )
            .await?;

        let event = self
            .get_event(connection.as_connection(), "Deposited", tx_info)
            .await?;

        Self::extract_leaf_idx_from_event(&event).map(|idx| {
            info!("Successfully deposited tokens.");
            idx
        })
    }

    /// Call `merge` message of the contract.
    #[allow(clippy::too_many_arguments)]
    pub async fn merge(
        &self,
        connection: &SignedConnection,
        token_id: FrontendTokenId,
        merkle_root: FrontendMerkleRoot,
        first_old_nullifier: FrontendNullifier,
        second_old_nullifier: FrontendNullifier,
        new_note: FrontendNote,
        proof: &[u8],
    ) -> Result<u32> {
        let ink_contract: Instance = (&self.contract).into();

        let tx_info = ink_contract
            .merge(
                connection,
                token_id,
                merkle_root,
                first_old_nullifier,
                second_old_nullifier,
                new_note,
                proof.to_vec(),
            )
            .await?;

        let event = self
            .get_event(connection.as_connection(), "Merged", tx_info)
            .await?;

        Self::extract_leaf_idx_from_event(&event).map(|idx| {
            info!("Successfully merged tokens.");
            idx
        })
    }

    /// Fetch the current merkle root.
    pub async fn get_merkle_root(&self, connection: &SignedConnection) -> FrontendMerkleRoot {
        self.contract
            .contract_read0(connection, "current_merkle_root")
            .await
            .unwrap()
    }

    /// Fetch the current merkle root.
<<<<<<< HEAD
    pub async fn get_voting_result(&self, connection: &SignedConnection) -> [u16; 144] {
=======
    pub async fn get_voting_result(&self, connection: &SignedConnection) -> [u64; 26] {
>>>>>>> 2fb01f68235bee2c2fad8769cc8239665862ad4b
        self.contract
            .contract_read0(connection, "current_voting_result")
            .await
            .unwrap()
    }

    /// Fetch the current merkle root.
    pub async fn get_merkle_path(
        &self,
        connection: &SignedConnection,
        leaf_idx: u32,
    ) -> Option<FrontendMerklePath> {
        self.contract
            .contract_read(connection, "merkle_path", &[&*leaf_idx.to_string()])
            .await
            .unwrap()
    }

    async fn get_event<'a>(
        &'a self,
        connection: &'a Connection,
        event_type: &'static str,
        tx_info: TxInfo,
    ) -> Result<ContractEvent> {
        let events = get_contract_events(connection, &self.contract, tx_info).await?;
        match &*events {
            [event] if event.name == Some(event_type.into()) => Ok(event.clone()),
            _ => Err(anyhow!(
                "Expected a single `{event_type}` event to be emitted. Found: {events:?}"
            )),
        }
    }

    fn extract_leaf_idx_from_event(event: &ContractEvent) -> Result<u32> {
        if let Some(leaf_idx) = event.data.get("leaf_idx") {
            let leaf_idx = ConvertibleValue(leaf_idx.clone()).try_into()?;
            Ok(leaf_idx)
        } else {
            Err(anyhow!("Failed to read event data"))
        }
    }
}
