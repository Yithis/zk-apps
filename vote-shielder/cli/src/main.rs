use std::{env, io, ops::Add, str::FromStr};

use aleph_client::{account_from_keypair, keypair_from_string, Connection, SignedConnection};
use anyhow::{anyhow, Result};
use ark_bls12_381::{Bls12_381, Fr};
<<<<<<< HEAD
use ark_ec::{
    pairing::{Pairing, PairingOutput},
    AffineRepr, CurveGroup,
};
use ark_ff::{BigInteger, BigInteger256, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{cfg_into_iter, One, UniformRand, Zero};
use clap::Parser;
use config::{DepositCmd, LoggingFormat, MergeCmd, VoteCmd, WithdrawCmd};
use inquire::{CustomType, Password, Select};
use liminal_ark_relations::{environment::CircuitField, shielder::types::FrontendTokenAmount};
use rand::{rngs::StdRng, SeedableRng};
use saver::prelude::PreparedDecryptionKey;
=======
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, BigInteger256, PrimeField};
use ark_serialize::CanonicalSerialize;
use ark_std::{cfg_into_iter, One, UniformRand};
use clap::Parser;
use config::{DepositCmd, LoggingFormat, MergeCmd, VoteCmd, WithdrawCmd};
use inquire::{CustomType, Password, Select};
use liminal_ark_relations::shielder::types::FrontendTokenAmount;
use rand::{rngs::StdRng, SeedableRng};
>>>>>>> 2fb01f68235bee2c2fad8769cc8239665862ad4b
use shielder::{
    app_state::AppState, contract::Shielder, deposit::*, merge::*, vote::*, withdraw::*,
};
use tracing::info;
use tracing_subscriber::EnvFilter;
use ContractInteractionCommand::{Deposit, Merge, Vote, Withdraw};
<<<<<<< HEAD
use EncryptionCommand::Decrypt;
=======
use EncryptionCommand::{Decrypt, Encrypt};
>>>>>>> 2fb01f68235bee2c2fad8769cc8239665862ad4b
use StateReadCommand::{PrintState, ShowAssets};
use StateWriteCommand::{SetContractAddress, SetNode};

extern crate shielder;

use ark_ff::fields::field_hashers::{DefaultFieldHasher, HashToField};
use sha2::Sha256;

use crate::{
    config::{
        CliConfig,
        Command::{ContractInteraction, Encryption, StateRead, StateWrite},
        ContractInteractionCommand, EncryptionCommand, StateReadCommand, StateWriteCommand,
    },
    state_file::{get_app_state, save_app_state},
};

mod config;
mod state_file;

fn perform_state_write_action(app_state: &mut AppState, command: StateWriteCommand) -> Result<()> {
    match command {
        SetNode { node } => {
            app_state.node_address = node;
        }
        SetContractAddress { address } => {
            app_state.contract_address = address;
        }
    };
    Ok(())
}

fn perform_state_read_action(app_state: &AppState, command: StateReadCommand) -> Result<()> {
    match command {
        ShowAssets { token_id } => {
            let assets = match token_id {
                None => app_state.get_all_assets(),
                Some(token_id) => app_state.get_single_asset(token_id),
            };
            info!(?assets)
        }
        PrintState => {
            info!(
                node_address=%app_state.node_address,
                contract_address=%app_state.contract_address,
                deposits=?app_state.deposits()
            )
        }
    };
    Ok(())
}

async fn perform_contract_action(
    app_state: &mut AppState,
    command: ContractInteractionCommand,
) -> Result<()> {
    let connection = Connection::new(&app_state.node_address).await;

    let metadata_file = command.get_metadata_file();
    let contract = Shielder::new(&app_state.contract_address, &metadata_file)?;

    match command {
        Deposit(cmd) => do_deposit(contract, connection, cmd, app_state).await?,
        Withdraw(cmd) => do_withdraw(contract, connection, cmd, app_state).await?,
        Merge(cmd) => do_merge(contract, connection, cmd, app_state).await?,
        Vote(cmd) => do_vote(contract, connection, cmd, app_state).await?,
    };
    Ok(())
}

<<<<<<< HEAD
fn solve_discrete_log(
    chunk_max_val: u16,
    g_i_v_i: PairingOutput<Bls12_381>,
    p: PairingOutput<Bls12_381>,
) -> crate::Result<u16> {
    if p == g_i_v_i {
        return Ok(1);
    }
    let mut cur = g_i_v_i;
    for j in 2..=chunk_max_val {
        cur += g_i_v_i;
        if cur == p {
            return Ok(j);
        }
    }
    Err(anyhow!("Could not solve discrete log"))
}

async fn perform_encryption_action(app_state: &AppState, command: EncryptionCommand) -> Result<()> {
    let connection = Connection::new(&app_state.node_address).await;

    let metadata_file = config::parsing::parse_path("shielder-metadata.json")?;
    let contract = Shielder::new(&app_state.contract_address, &metadata_file)?;
    match command {
        Decrypt {} => {
            let connection =
                SignedConnection::from_connection(connection, keypair_from_string("//0"));
            let voting_result = contract.get_voting_result(&connection).await;
            info!(?voting_result);

            let mut voting_result_u8 = [0u8; 144];
            for i in 0..144 {
                voting_result_u8[i] = voting_result[i].try_into().unwrap();
            }

            let mut rng = StdRng::seed_from_u64(0u64);
            //let mut rng1 = StdRng::seed_from_u64(1u64);
            let message = ark_bls12_381::Fr::from(4u64);
            let _message1 = ark_bls12_381::Fr::from(u64::from_le_bytes([6, 0, 0, 0, 0, 0, 0, 0]));
            let chunk_bit_size = 16;
            let enc_gens = saver::setup::EncryptionGens::<Bls12_381>::new_using_rng(&mut rng);
            //let enc_gens1 = saver::setup::EncryptionGens::<Bls12_381>::new_using_rng(&mut rng1);
            let (snark_srs, sk, _ek, dk) =
                saver::setup::setup_for_groth16(&mut rng, chunk_bit_size, &enc_gens).unwrap();
            let g_i = saver::saver_groth16::get_gs_for_encryption(&snark_srs.pk.vk);

            let dk: PreparedDecryptionKey<Bls12_381> = dk.into();

            let c_0: <Bls12_381 as Pairing>::G1Affine =
                <Bls12_381 as Pairing>::G1Affine::deserialize_compressed(&voting_result_u8[0..48])
                    .unwrap();
            let c: Vec<<Bls12_381 as Pairing>::G1Affine> = vec![
                <Bls12_381 as Pairing>::G1Affine::deserialize_compressed(&voting_result_u8[48..96])
                    .unwrap(),
                <Bls12_381 as Pairing>::G1Affine::deserialize_compressed(
                    &voting_result_u8[96..144],
                )
                .unwrap(),
            ];

            let c_0_rho = c_0.mul_bigint((-sk.0).into_bigint());
            let c_0_rho_prepared = <Bls12_381 as Pairing>::G1Prepared::from(c_0_rho.into_affine());
            let mut decrypted_chunks = vec![];
            let chunk_max_val: u32 = (1 << chunk_bit_size) - 1;
            for i in 0..2 {
                let p = <Bls12_381 as Pairing>::multi_pairing(
                    [c[i].into(), c_0_rho_prepared.clone()],
                    [dk.V_2[i].clone(), dk.V_1[i].clone()],
                );
                if p.is_zero() {
                    decrypted_chunks.push(0);
                    continue;
                }

                // Precomputed powers are not provided, compute the necessary pairings
                let g_i_v_i = <Bls12_381 as Pairing>::pairing(
                    <Bls12_381 as Pairing>::G1Prepared::from(g_i[i]),
                    dk.V_2[i].clone(),
                );
                decrypted_chunks.push(solve_discrete_log(chunk_max_val as u16, g_i_v_i, p)?);
            }
            info!(?decrypted_chunks);
=======
fn perform_encryption_action(app_state: &AppState, command: EncryptionCommand) -> Result<()> {
    match command {
        Encrypt { message } => {
            let mut rng = StdRng::seed_from_u64(0u64);
            //let mut rng1 = StdRng::seed_from_u64(1u64);
            let message = ark_bls12_381::Fr::from(4u64);
            let message1 = ark_bls12_381::Fr::from(u64::from_le_bytes([6, 0, 0, 0, 0, 0, 0, 0]));
            let chunk_bit_size = 16;
            let enc_gens = saver::setup::EncryptionGens::<Bls12_381>::new_using_rng(&mut rng);
            //let enc_gens1 = saver::setup::EncryptionGens::<Bls12_381>::new_using_rng(&mut rng1);
            let (snark_srs, _sk, ek, _dk) =
                saver::setup::setup_for_groth16(&mut rng, chunk_bit_size, &enc_gens).unwrap();
            //let (snark_srs, _sk, ek, _dk) =
            //    saver::setup::setup_for_groth16(&mut rng1, chunk_bit_size, &enc_gens1).unwrap();
            let gs = saver::saver_groth16::get_gs_for_encryption(&snark_srs.pk.vk);
            let result = saver::encryption::Encryption::<Bls12_381>::encrypt_given_snark_vk(
                &mut rng,
                &message,
                &ek,
                &snark_srs.pk.vk,
                chunk_bit_size,
            )
            .unwrap();
            let dec = saver::utils::decompose(&message, chunk_bit_size).unwrap();

            let mut m = cfg_into_iter!(dec)
                .map(|m_i| <ark_bls12_381::fr::Fr as PrimeField>::BigInt::from(m_i as u64))
                .collect::<Vec<_>>();

            println!("X_2: {:?}", ek.X[1]);
            println!("r: {:?}", result.1.into_bigint());
            println!("G_2: {:?}", gs[1]);

            let q = ek.X[0]
                .mul_bigint(result.1.into_bigint())
                .add(gs[0].mul_bigint(BigInteger256::from(4u64)));
            let r = ek.X[1]
                .mul_bigint(result.1.into_bigint())
                .add(gs[1].mul_bigint(BigInteger256::from(6u64)));
            info!(
                "{}",
                ek.X[0]
                    .mul_bigint(result.1.into_bigint())
                    .add(gs[0].mul_bigint(BigInteger256::from(4u64)))
            );
            info!(
                "{}",
                ek.X[1]
                    .mul_bigint(result.1.into_bigint())
                    .add(gs[1].mul_bigint(m[1]))
                    .compressed_size()
            );
            info!(
                "{}",
                ek.X[0]
                    .mul_bigint(result.1.into_bigint())
                    .add(gs[0].mul_bigint(m[0]))
                    .eq(&result.0.enc_chunks[1])
            );
            let mut hash = [0u8; 48];
            q.serialize_compressed(&mut hash[..]);
            info!("q {:?}", hash);

            let hasher =
                <DefaultFieldHasher<Sha256> as HashToField<ark_bls12_381::Fr>>::new(&[1, 2, 3]);
            let field_elements: Vec<ark_bls12_381::Fr> = hasher.hash_to_field(&hash, 1);
            info!("{:?}", field_elements[0]);
            let field_elements = field_elements[0].into_bigint();
            info!("{:?}", field_elements.to_bytes_le());
            r.serialize_compressed(&mut hash[..]);
            info!("r {:?}", hash);

            let field_elements: Vec<ark_bls12_381::Fr> = hasher.hash_to_field(&hash, 1);
            info!("{:?}", field_elements[0]);
            let field_elements = field_elements[0].into_bigint();

            info!("{:?}", field_elements.to_bytes_le());

            let mut x = [0u8; 48];
            ek.X[0].serialize_compressed(&mut x[..]);
            info!("{:?}", x);
            gs[0].serialize_compressed(&mut x[..]);
            info!("{:?}", x);
            ek.X[1].serialize_compressed(&mut x[..]);
            info!("{:?}", x);
            gs[1].serialize_compressed(&mut x[..]);
            info!("{:?}", x);
            result.1.serialize_compressed(&mut x[..]);
            info!("{:?}", x);

            //info!("{}", std::mem::size_of_val(&result));
            //info!("{}", std::mem::size_of_val(&ek.X[0]));
            //info!("{}", std::mem::size_of_val(&gs[0]));
            //info!("{}", std::mem::size_of_val(&result.enc_chunks[0]));
            //info!(
            //    "{}",
            //    std::mem::size_of_val(&result.enc_chunks[0].compressed_size())
            //);
            //info!(
            //    "{}",
            //    std::mem::size_of_val(&result.enc_chunks[1].compressed_size())
            //);
            //info!(?result);
        }
        Decrypt { ciphertext } => {
            let mut rng = StdRng::seed_from_u64(0u64);
            let message = Fr::one();
            let chunk_bit_size = 8;
            let enc_gens = saver::setup::EncryptionGens::<Bls12_381>::new_using_rng(&mut rng);
            let (snark_srs, sk, ek, dk) =
                saver::setup::setup_for_groth16(&mut rng, chunk_bit_size, &enc_gens).unwrap();
            let first = saver::encryption::Encryption::<Bls12_381>::encrypt_given_snark_vk(
                &mut rng,
                &message,
                &ek,
                &snark_srs.pk.vk,
                chunk_bit_size,
            )
            .unwrap()
            .0;
            let second = saver::encryption::Encryption::<Bls12_381>::encrypt_given_snark_vk(
                &mut rng,
                &message,
                &ek,
                &snark_srs.pk.vk,
                chunk_bit_size,
            )
            .unwrap()
            .0;
            let ciphertext = saver::encryption::Ciphertext::<_> {
                X_r: (first.X_r + second.X_r).into_affine(),
                enc_chunks: cfg_into_iter!(first.enc_chunks)
                    .zip(cfg_into_iter!(second.enc_chunks))
                    .map(|(a, b)| (a + b).into_affine())
                    .collect(),
                commitment: (first.commitment + second.commitment).into_affine(),
            };
            let result = ciphertext.decrypt_given_groth16_vk(
                &sk,
                dk.clone(),
                &snark_srs.pk.vk,
                chunk_bit_size,
            );
            info!(?result)
>>>>>>> 2fb01f68235bee2c2fad8769cc8239665862ad4b
        }
    };
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli_config: CliConfig = CliConfig::parse();

    init_logging(cli_config.logging_format)?;

    let password = match cli_config.password {
        Some(password) => password,
        _ => Password::new("Password (for encrypting local state):")
            .without_confirmation()
            .prompt()?,
    };

    let mut app_state = get_app_state(&cli_config.state_file, &password)?;

    match cli_config.command {
        StateWrite(cmd) => {
            perform_state_write_action(&mut app_state, cmd)?;
            save_app_state(&app_state, &cli_config.state_file, &password)?;
        }
        StateRead(cmd) => perform_state_read_action(&app_state, cmd)?,
        ContractInteraction(cmd) => {
            perform_contract_action(&mut app_state, cmd).await?;
            save_app_state(&app_state, &cli_config.state_file, &password)?;
        }
<<<<<<< HEAD
        Encryption(cmd) => perform_encryption_action(&app_state, cmd).await?,
=======
        Encryption(cmd) => perform_encryption_action(&app_state, cmd)?,
>>>>>>> 2fb01f68235bee2c2fad8769cc8239665862ad4b
    }

    Ok(())
}

const LOG_CONFIGURATION_ENVVAR: &str = "RUST_LOG";

fn init_logging(format: LoggingFormat) -> Result<()> {
    // We need to disable logging in our dependency crates by default.
    let filter = EnvFilter::new(
        env::var(LOG_CONFIGURATION_ENVVAR)
            .as_deref()
            .unwrap_or("warn,shielder_cli=info"),
    );

    let subscriber = tracing_subscriber::fmt()
        .with_writer(io::stdout)
        .with_target(false)
        .with_env_filter(filter);

    match format {
        LoggingFormat::Json => subscriber.json().try_init(),
        LoggingFormat::Text => subscriber.try_init(),
    }
    .map_err(|err| anyhow!(err))
}

async fn do_deposit(
    contract: Shielder,
    connection: Connection,
    cmd: DepositCmd,
    app_state: &mut AppState,
) -> Result<()> {
    let DepositCmd {
        token_id,
        amount,
        caller_seed,
        require_new_deposit,
        ..
    } = cmd;

    let seed = match caller_seed {
        Some(seed) => seed,
        None => Password::new("Seed of the depositing account (the tokens owner):")
            .without_confirmation()
            .prompt()?,
    };
    let connection = SignedConnection::from_connection(connection, keypair_from_string(&seed));

    let old_deposit = app_state.get_last_deposit(token_id);

    match (old_deposit, require_new_deposit) {
        (Some(old_deposit), false) => {
            let _ = deposit_and_merge(
                old_deposit,
                amount,
                &cmd.deposit_and_merge_key_file,
                &connection,
                &contract,
                app_state,
            )
            .await?;
            Ok(())
        }
        (_, _) => {
            let _ = new_deposit(
                token_id,
                amount,
                &cmd.deposit_key_file,
                &connection,
                &contract,
                app_state,
            )
            .await?;
            Ok(())
        }
    }
}

async fn do_vote(
    contract: Shielder,
    connection: Connection,
    cmd: VoteCmd,
    app_state: &mut AppState,
) -> Result<()> {
    let VoteCmd {
        token_id,
        first_vote,
        second_vote,
        caller_seed,
        vote_key_file,
        ..
    } = cmd;

    let caller_seed = match caller_seed {
        Some(seed) => seed,
        None => Password::new("Seed of the vote account (the caller, not necessarily recipient):")
            .without_confirmation()
            .prompt()?,
    };

    let deposit = app_state.get_last_deposit(token_id).unwrap();

    let signer = keypair_from_string(&caller_seed);

    let connection = SignedConnection::from_connection(connection, signer);

    let mut rng = StdRng::seed_from_u64(0u64);
<<<<<<< HEAD

    let message = vec![first_vote, second_vote];

    let chunk_bit_size = 16;
    let enc_gens = saver::setup::EncryptionGens::<Bls12_381>::new_using_rng(&mut rng);
    let (snark_srs, _sk, ek, _dk) =
        saver::setup::setup_for_groth16(&mut rng, chunk_bit_size, &enc_gens).unwrap();

    let hasher = <DefaultFieldHasher<Sha256> as HashToField<ark_bls12_381::Fr>>::new(&[1, 2, 3]);

    let g_i = saver::saver_groth16::get_gs_for_encryption(&snark_srs.pk.vk);

    let r = <Bls12_381 as Pairing>::ScalarField::rand(&mut rng);
    let r_repr = r.into_bigint();
    let mut ct = vec![];
    ct.push(ek.X_0.mul_bigint(r_repr));
    let mut m = cfg_into_iter!(message)
        .map(|m_i| <<Bls12_381 as Pairing>::ScalarField as PrimeField>::BigInt::from(m_i as u64))
        .collect::<Vec<_>>();
    for i in 0..2 {
        ct.push(ek.X[i].mul_bigint(r_repr).add(g_i[i].mul_bigint(m[i])));
    }
    ct.push(<Bls12_381 as Pairing>::G1::zero());
    let mut ct = <Bls12_381 as Pairing>::G1::normalize_batch(&ct);
    let encrypted_vote = saver::encryption::Ciphertext::<Bls12_381> {
        X_r: ct.remove(0),
        commitment: ct.remove(ct.len() - 1),
        enc_chunks: ct,
    };

    let mut encrypted_x_r_serialized = [0u8; 48];
    encrypted_vote
        .X_r
        .serialize_compressed(encrypted_x_r_serialized.as_mut_slice())
        .unwrap();

    let mut encrypted_first_vote_serialized = [0u8; 48];
    encrypted_vote.enc_chunks[0]
        .serialize_compressed(encrypted_first_vote_serialized.as_mut_slice())
        .unwrap();
    let first_vote_hash: CircuitField =
        hasher.hash_to_field(&encrypted_first_vote_serialized.clone(), 1)[0];
    let mut first_vote_hash_serialized = [0u64; 4];

    let mut temp = [0u8; 32];
    first_vote_hash
        .serialize_compressed(temp.as_mut_slice())
        .unwrap();

    for i in 0..4 {
        first_vote_hash_serialized[i] =
            u64::from_le_bytes(temp[8 * i..8 * (i + 1)].try_into().unwrap());
    }

    let mut encrypted_second_vote_serialized = [0u8; 48];
    encrypted_vote.enc_chunks[1]
        .serialize_compressed(encrypted_second_vote_serialized.as_mut_slice())
        .unwrap();
    let second_vote_hash: CircuitField =
        hasher.hash_to_field(&encrypted_second_vote_serialized.clone(), 1)[0];
    let mut second_vote_hash_serialized = [0u64; 4];

    let mut temp = [0u8; 32];
    second_vote_hash
        .serialize_compressed(temp.as_mut_slice())
        .unwrap();

    for i in 0..4 {
        second_vote_hash_serialized[i] =
            u64::from_le_bytes(temp[8 * i..8 * (i + 1)].try_into().unwrap());
    }

    let mut vote_randomness_bytes = [0u8; 32];
    let mut vote_randomness = [0u64; 4];
    r.serialize_compressed(vote_randomness_bytes.as_mut_slice())
        .expect("succesfully serialize");

    for i in 0..4 {
        vote_randomness[i] = u64::from_le_bytes(
            vote_randomness_bytes[8 * i..8 * (i + 1)]
                .try_into()
                .unwrap(),
        );
    }

    vote(
        &contract,
        &connection,
        deposit,
        first_vote_hash_serialized,
        second_vote_hash_serialized,
        encrypted_x_r_serialized,
        encrypted_first_vote_serialized,
        encrypted_second_vote_serialized,
        first_vote,
        second_vote,
        vote_randomness,
        &vote_key_file,
        app_state,
    )
    .await
=======
    let message = Fr::from_str(&(first_vote.to_string() + &second_vote.to_string())).unwrap();
    let chunk_bit_size = 8;
    let enc_gens = saver::setup::EncryptionGens::<Bls12_381>::new_using_rng(&mut rng);
    let (snark_srs, _sk, ek, _dk) =
        saver::setup::setup_for_groth16(&mut rng, chunk_bit_size, &enc_gens).unwrap();
    let first_vote_hash = saver::encryption::Encryption::<Bls12_381>::encrypt_given_snark_vk(
        &mut rng,
        &message,
        &ek,
        &snark_srs.pk.vk,
        chunk_bit_size,
    );
    let second_vote_hash = saver::encryption::Encryption::<Bls12_381>::encrypt_given_snark_vk(
        &mut rng,
        &message,
        &ek,
        &snark_srs.pk.vk,
        chunk_bit_size,
    );
    let mut hash = [0u8; 48];
    let hasher = <DefaultFieldHasher<Sha256> as HashToField<CircuitField>>::new(&[1, 2, 3]);

    let mut encrypted_vote = [0u64; 4];
    let mut temp = [0u8; 32];
    encrypted_vote.serialize_compressed(temp.as_mut_slice());

    for i in 0..4 {
        encrypted_vote[i] = u64::from_le_bytes(temp[8 * i..8 * (i + 1)].try_into().unwrap());
    }
    Ok(())

    //vote(
    //    &contract,
    //    &connection,
    //    deposit,
    //    encrypted_vote,
    //    first_vote,
    //    second_vote,
    //    &vote_key_file,
    //    app_state,
    //)
    //.await
>>>>>>> 2fb01f68235bee2c2fad8769cc8239665862ad4b
}

async fn do_merge(
    contract: Shielder,
    connection: Connection,
    cmd: MergeCmd,
    app_state: &mut AppState,
) -> Result<()> {
    let MergeCmd {
        first_deposit_id,
        second_deposit_id,
        caller_seed,
        proving_key_file,
        ..
    } = cmd;

    let seed = match caller_seed {
        Some(seed) => seed,
        None => Password::new("Seed of the merging account (the tokens owner):")
            .without_confirmation()
            .prompt()?,
    };
    let connection = SignedConnection::from_connection(connection, keypair_from_string(&seed));

    let first_deposit = app_state
        .get_deposit_by_id(first_deposit_id)
        .ok_or(anyhow!("Cannot match first deposit id to actual deposit!"))?;
    let second_deposit = app_state
        .get_deposit_by_id(second_deposit_id)
        .ok_or(anyhow!("Cannot match second deposit id to actual deposit!"))?;

    anyhow::ensure!(
        first_deposit != second_deposit,
        "Cannot merge a deposit with itself!"
    );

    let first_token_id = first_deposit.token_id;
    let second_token_id = second_deposit.token_id;

    anyhow::ensure!(
        first_token_id == second_token_id,
        "Cannot merge deposits with different token ids!"
    );

    merge(
        first_deposit,
        second_deposit,
        &proving_key_file,
        &connection,
        &contract,
        app_state,
    )
    .await?;

    Ok(())
}

async fn do_withdraw(
    contract: Shielder,
    connection: Connection,
    cmd: WithdrawCmd,
    app_state: &mut AppState,
) -> Result<()> {
    let (deposit, withdraw_amount) = get_deposit_and_withdraw_amount(&cmd, app_state)?;

    let WithdrawCmd {
        recipient,
        caller_seed,
        fee,
        proving_key_file,
        ..
    } = cmd;

    let caller_seed = match caller_seed {
        Some(seed) => seed,
        None => Password::new(
            "Seed of the withdrawing account (the caller, not necessarily recipient):",
        )
        .without_confirmation()
        .prompt()?,
    };

    let signer = keypair_from_string(&caller_seed);
    let recipient = match recipient {
        Some(recipient) => recipient,
        None => account_from_keypair(signer.signer()),
    };

    let connection = SignedConnection::from_connection(connection, signer);

    withdraw(
        &contract,
        &connection,
        deposit,
        withdraw_amount,
        &recipient,
        fee,
        &proving_key_file,
        app_state,
    )
    .await
}

fn get_deposit_and_withdraw_amount(
    cmd: &WithdrawCmd,
    app_state: &AppState,
) -> Result<(shielder::app_state::Deposit, FrontendTokenAmount)> {
    if !cmd.interactive {
        if let Some(deposit) = app_state.get_deposit_by_id(cmd.deposit_id.unwrap()) {
            return Ok((deposit, cmd.amount.unwrap()));
        }
        return Err(anyhow!("Incorrect deposit id"));
    }

    let deposit = Select::new("Select one of your deposits:", app_state.deposits())
        .with_page_size(5)
        .prompt()?;

    let amount =
        CustomType::<FrontendTokenAmount>::new("Specify how many tokens should be withdrawn:")
            .with_default(deposit.token_amount)
            .with_parser(&|a| match str::parse::<FrontendTokenAmount>(a) {
                Ok(amount) if amount <= deposit.token_amount => Ok(amount),
                _ => Err(()),
            })
            .with_error_message(
                "You should provide a valid amount, no more than the whole deposit value",
            )
            .prompt()?;

    Ok((deposit, amount))
}
