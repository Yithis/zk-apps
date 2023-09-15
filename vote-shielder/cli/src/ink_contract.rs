use scale::Encode as _;

// This file was auto-generated with ink-wrapper (https://crates.io/crates/ink-wrapper).

#[derive(Debug, Clone, PartialEq, Eq, scale::Encode, scale::Decode)]
pub enum ShielderError {
    InsufficientPermission(OwnableError),
    TooManyNotes(),
    UnknownMerkleRoot(),
    NullifierAlreadyUsed(),
    TooHighFee(),
    ChainExtension(BabyLiminalError),
    Psp22(PSP22Error),
    InkEnv(String),
    TokenIdAlreadyRegistered(),
    TokenIdNotRegistered(),
}

#[derive(Debug, Clone, PartialEq, Eq, scale::Encode, scale::Decode)]
pub enum OwnableError {
    CallerIsNotOwner(),
    NewOwnerIsZero(),
}

#[derive(Debug, Clone, PartialEq, Eq, scale::Encode, scale::Decode)]
pub enum BabyLiminalError {
    IdentifierAlreadyInUse(),
    VerificationKeyTooLong(),
    StoreKeyErrorUnknown(),
    UnknownVerificationKeyIdentifier(),
    DeserializingProofFailed(),
    DeserializingPublicInputFailed(),
    DeserializingVerificationKeyFailed(),
    VerificationFailed(),
    IncorrectProof(),
    VerifyErrorUnknown(),
}

#[derive(Debug, Clone, PartialEq, Eq, scale::Encode, scale::Decode)]
pub enum PSP22Error {
    Custom(Vec<u8>),
    InsufficientBalance(),
    InsufficientAllowance(),
    ZeroRecipientAddress(),
    ZeroSenderAddress(),
    SafeTransferCheckFailed(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq, scale::Encode, scale::Decode)]
pub enum Relation {
    Deposit(),
    DepositAndMerge(),
    Merge(),
    Withdraw(),
    Vote(),
}

pub mod event {
    #[allow(dead_code, clippy::large_enum_variant)]
    #[derive(Debug, Clone, PartialEq, Eq, scale::Encode, scale::Decode)]
    pub enum Event {
        Deposited {
            token_id: u16,
            value: u128,
            leaf_idx: u32,
            note: [u64; 4],
        },

        Withdrawn {
            token_id: u16,
            value: u128,
            recipient: ink_primitives::AccountId,
            leaf_idx: u32,
            new_note: [u64; 4],
        },

        Voted {
            token_id: u16,
            token_amount: u128,
        },

        TokenRegistered {
            token_id: u16,
            token_address: ink_primitives::AccountId,
        },

        Merged {
            token_id: u16,
            leaf_idx: u32,
            new_note: [u64; 4],
        },
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Instance {
    account_id: ink_primitives::AccountId,
}

impl From<ink_primitives::AccountId> for Instance {
    fn from(account_id: ink_primitives::AccountId) -> Self {
        Self { account_id }
    }
}

impl From<Instance> for ink_primitives::AccountId {
    fn from(instance: Instance) -> Self {
        instance.account_id
    }
}

impl ink_wrapper_types::EventSource for Instance {
    type Event = event::Event;
}

impl Instance {
    /// Instantiate the contract. Set the caller as the owner.
    #[allow(dead_code, clippy::too_many_arguments)]
    pub async fn new<TxInfo, E, C: ink_wrapper_types::SignedConnection<TxInfo, E>>(
        conn: &C,
        salt: Vec<u8>,
        max_leaves: u32,
    ) -> Result<Self, E> {
        let data = {
            let mut data = vec![155, 174, 157, 94];
            max_leaves.encode_to(&mut data);
            data
        };
        let code_hash = [
            147, 235, 61, 186, 178, 110, 205, 104, 158, 86, 65, 35, 172, 133, 253, 90, 250, 128,
            225, 225, 205, 101, 131, 218, 124, 140, 108, 114, 2, 153, 128, 42,
        ];
        let account_id = conn.instantiate(code_hash, salt, data).await?;
        Ok(Self { account_id })
    }

    ///  Trigger deposit action (see ADR for detailed description).
    #[allow(dead_code, clippy::too_many_arguments)]
    pub async fn deposit<TxInfo, E, C: ink_wrapper_types::SignedConnection<TxInfo, E>>(
        &self,
        conn: &C,
        token_id: u16,
        value: u128,
        note: [u64; 4],
        proof: Vec<u8>,
    ) -> Result<TxInfo, E> {
        let data = {
            let mut data = vec![0, 0, 0, 1];
            token_id.encode_to(&mut data);
            value.encode_to(&mut data);
            note.encode_to(&mut data);
            proof.encode_to(&mut data);
            data
        };
        conn.exec(self.account_id, data).await
    }

    ///  Trigger withdraw action (see ADR for detailed description).
    #[allow(dead_code, clippy::too_many_arguments)]
    pub async fn withdraw<TxInfo, E, C: ink_wrapper_types::SignedConnection<TxInfo, E>>(
        &self,
        conn: &C,
        token_id: u16,
        value: u128,
        recipient: ink_primitives::AccountId,
        fee_for_caller: Option<u128>,
        merkle_root: [u64; 4],
        nullifier: [u64; 4],
        new_note: [u64; 4],
        proof: Vec<u8>,
    ) -> Result<TxInfo, E> {
        let data = {
            let mut data = vec![0, 0, 0, 2];
            token_id.encode_to(&mut data);
            value.encode_to(&mut data);
            recipient.encode_to(&mut data);
            fee_for_caller.encode_to(&mut data);
            merkle_root.encode_to(&mut data);
            nullifier.encode_to(&mut data);
            new_note.encode_to(&mut data);
            proof.encode_to(&mut data);
            data
        };
        conn.exec(self.account_id, data).await
    }

    ///  Read the current root of the Merkle tree with notes.
    #[allow(dead_code, clippy::too_many_arguments)]
    pub async fn current_merkle_root<TxInfo, E, C: ink_wrapper_types::Connection<TxInfo, E>>(
        &self,
        conn: &C,
    ) -> Result<Result<[u64; 4], ink_wrapper_types::InkLangError>, E> {
        let data = vec![0, 0, 0, 3];
        conn.read(self.account_id, data).await
    }

    ///  Retrieve the path from the leaf to the root. `None` if the leaf does not exist.
    #[allow(dead_code, clippy::too_many_arguments)]
    pub async fn merkle_path<TxInfo, E, C: ink_wrapper_types::Connection<TxInfo, E>>(
        &self,
        conn: &C,
        leaf_idx: u32,
    ) -> Result<Result<Option<Vec<[u64; 4]>>, ink_wrapper_types::InkLangError>, E> {
        let data = {
            let mut data = vec![0, 0, 0, 4];
            leaf_idx.encode_to(&mut data);
            data
        };
        conn.read(self.account_id, data).await
    }

    ///  Check whether `nullifier` has been already used.
    #[allow(dead_code, clippy::too_many_arguments)]
    pub async fn contains_nullifier<TxInfo, E, C: ink_wrapper_types::Connection<TxInfo, E>>(
        &self,
        conn: &C,
        nullifier: [u64; 4],
    ) -> Result<Result<bool, ink_wrapper_types::InkLangError>, E> {
        let data = {
            let mut data = vec![0, 0, 0, 5];
            nullifier.encode_to(&mut data);
            data
        };
        conn.read(self.account_id, data).await
    }

    ///  Register a verifying key for one of the `Relation`.
    ///
    ///  For owner use only.
    #[allow(dead_code, clippy::too_many_arguments)]
    pub async fn register_vk<TxInfo, E, C: ink_wrapper_types::SignedConnection<TxInfo, E>>(
        &self,
        conn: &C,
        relation: Relation,
        vk: Vec<u8>,
    ) -> Result<TxInfo, E> {
        let data = {
            let mut data = vec![0, 0, 0, 8];
            relation.encode_to(&mut data);
            vk.encode_to(&mut data);
            data
        };
        conn.exec(self.account_id, data).await
    }

    ///  Check if there is a token address registered at `token_id`.
    #[allow(dead_code, clippy::too_many_arguments)]
    pub async fn registered_token_address<
        TxInfo,
        E,
        C: ink_wrapper_types::Connection<TxInfo, E>,
    >(
        &self,
        conn: &C,
        token_id: u16,
    ) -> Result<Result<Option<ink_primitives::AccountId>, ink_wrapper_types::InkLangError>, E> {
        let data = {
            let mut data = vec![0, 0, 0, 9];
            token_id.encode_to(&mut data);
            data
        };
        conn.read(self.account_id, data).await
    }

    ///  Register a token contract (`token_address`) at `token_id`.
    ///
    ///  For owner use only.
    #[allow(dead_code, clippy::too_many_arguments)]
    pub async fn register_new_token<
        TxInfo,
        E,
        C: ink_wrapper_types::SignedConnection<TxInfo, E>,
    >(
        &self,
        conn: &C,
        token_id: u16,
        token_address: ink_primitives::AccountId,
    ) -> Result<TxInfo, E> {
        let data = {
            let mut data = vec![0, 0, 0, 10];
            token_id.encode_to(&mut data);
            token_address.encode_to(&mut data);
            data
        };
        conn.exec(self.account_id, data).await
    }

    ///  Trigger deposit and merge action (see ADR for detailed description).
    #[allow(dead_code, clippy::too_many_arguments)]
    pub async fn deposit_and_merge<TxInfo, E, C: ink_wrapper_types::SignedConnection<TxInfo, E>>(
        &self,
        conn: &C,
        token_id: u16,
        value: u128,
        merkle_root: [u64; 4],
        nullifier: [u64; 4],
        note: [u64; 4],
        proof: Vec<u8>,
    ) -> Result<TxInfo, E> {
        let data = {
            let mut data = vec![0, 0, 0, 11];
            token_id.encode_to(&mut data);
            value.encode_to(&mut data);
            merkle_root.encode_to(&mut data);
            nullifier.encode_to(&mut data);
            note.encode_to(&mut data);
            proof.encode_to(&mut data);
            data
        };
        conn.exec(self.account_id, data).await
    }

    ///  Trigger merge action to combine the value of two notes.
    #[allow(dead_code, clippy::too_many_arguments)]
    pub async fn merge<TxInfo, E, C: ink_wrapper_types::SignedConnection<TxInfo, E>>(
        &self,
        conn: &C,
        token_id: u16,
        merkle_root: [u64; 4],
        first_nullifier: [u64; 4],
        second_nullifier: [u64; 4],
        note: [u64; 4],
        proof: Vec<u8>,
    ) -> Result<TxInfo, E> {
        let data = {
            let mut data = vec![0, 0, 0, 12];
            token_id.encode_to(&mut data);
            merkle_root.encode_to(&mut data);
            first_nullifier.encode_to(&mut data);
            second_nullifier.encode_to(&mut data);
            note.encode_to(&mut data);
            proof.encode_to(&mut data);
            data
        };
        conn.exec(self.account_id, data).await
    }

    ///  Trigger withdraw action (see ADR for detailed description).
    #[allow(dead_code, clippy::too_many_arguments)]
    pub async fn vote<TxInfo, E, C: ink_wrapper_types::SignedConnection<TxInfo, E>>(
        &self,
        conn: &C,
        token_id: u16,
        nullifier: [u64; 4],
        token_amount: u128,
        encrypted_vote: [u64; 26],
        merkle_root: [u64; 4],
        proof: Vec<u8>,
    ) -> Result<TxInfo, E> {
        let data = {
            let mut data = vec![0, 0, 0, 13];
            token_id.encode_to(&mut data);
            nullifier.encode_to(&mut data);
            token_amount.encode_to(&mut data);
            encrypted_vote.encode_to(&mut data);
            merkle_root.encode_to(&mut data);
            proof.encode_to(&mut data);
            data
        };
        conn.exec(self.account_id, data).await
    }

    ///  Read the current root of the Merkle tree with notes.
    #[allow(dead_code, clippy::too_many_arguments)]
    pub async fn current_voting_result<TxInfo, E, C: ink_wrapper_types::Connection<TxInfo, E>>(
        &self,
        conn: &C,
    ) -> Result<Result<[u64; 26], ink_wrapper_types::InkLangError>, E> {
        let data = vec![0, 0, 0, 14];
        conn.read(self.account_id, data).await
    }
}
