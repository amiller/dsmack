//! Read-only finalized-state verification. This binary never signs or submits.
use alloy::{
    consensus::BlockHeader,
    eips::BlockNumberOrTag,
    primitives::{keccak256, Address, B256, U256},
    rpc::types::TransactionRequest,
    sol_types::SolValue,
};
use eyre::{bail, ensure, Result};
use helios_ethereum::{config::networks::Network, database::ConfigDB, EthereumClientBuilder};
use serde::{Deserialize, Serialize};
use std::{
    fs::OpenOptions,
    io::Read,
    os::unix::fs::OpenOptionsExt,
    time::{SystemTime, UNIX_EPOCH},
};

const UPSTREAM: &str = "2af9b41887e069144ee56cd710f3ddca195473f8";
const PROFILE: &str = "helios-ethereum-sepolia-finalized-experiment";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    version: u8,
    trust_profile: String,
    chain_id: u64,
    genesis_validators_root: B256,
    bootstrap_checkpoint: B256,
    consensus_rpc: String,
    execution_rpc: String,
    guard_address: Address,
    guard_code_hash: B256,
    issuer_address: Address,
    issuance_policy_hash: B256,
    max_finalized_age_seconds: u64,
    timeout_seconds: u64,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    version: u8,
    coupon_digest: B256,
    recipient_commitment: B256,
    accepted_offer_hash: B256,
    process_nonce: B256,
}
#[derive(Serialize)]
struct FinalizedBlock {
    hash: B256,
    number: u64,
    timestamp: u64,
    state_root: B256,
    receipts_root: B256,
}
#[derive(Serialize)]
struct Guard {
    address: Address,
    code_hash: B256,
    issuer: Address,
    policy_hash: B256,
    coupon_digest: B256,
    consumed_commitment: B256,
}
#[derive(Serialize)]
struct Verdict {
    version: u8,
    trust_profile: &'static str,
    upstream_sha: &'static str,
    chain_id: u64,
    genesis_validators_root: B256,
    bootstrap_checkpoint: B256,
    finalized_block: FinalizedBlock,
    verified_at_ms: u64,
    freshness_basis: &'static str,
    guard: Guard,
}

fn read_json<T: serde::de::DeserializeOwned>(source: impl Read) -> Result<T> {
    let mut bytes = Vec::new();
    source.take(65_537).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 65_536, "input bound");
    Ok(serde_json::from_slice(&bytes)?)
}
fn unix_ms() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .try_into()?)
}
fn endpoint(value: &str) -> Result<()> {
    let u = url::Url::parse(value)?;
    ensure!(
        u.username().is_empty() && u.password().is_none() && u.fragment().is_none(),
        "endpoint authority"
    );
    ensure!(
        u.scheme() == "https"
            || (u.scheme() == "http"
                && matches!(u.host_str(), Some("127.0.0.1" | "[::1]" | "localhost"))),
        "endpoint transport"
    );
    Ok(())
}
fn validate(c: &Config, i: &Intent) -> Result<()> {
    let chain = Network::Sepolia.to_base_config().chain;
    ensure!(
        c.version == 1
            && c.trust_profile == PROFILE
            && c.chain_id == chain.chain_id
            && c.genesis_validators_root == chain.genesis_root,
        "experimental network pins"
    );
    ensure!(
        c.bootstrap_checkpoint != B256::ZERO
            && c.guard_address != Address::ZERO
            && c.guard_code_hash != B256::ZERO
            && c.issuer_address != Address::ZERO
            && c.issuance_policy_hash != B256::ZERO,
        "protected authority pins"
    );
    ensure!(
        (60..=7200).contains(&c.max_finalized_age_seconds)
            && (1..=300).contains(&c.timeout_seconds),
        "lifetime bounds"
    );
    ensure!(
        i.version == 1
            && [
                i.coupon_digest,
                i.recipient_commitment,
                i.accepted_offer_hash,
                i.process_nonce
            ]
            .iter()
            .all(|v| *v != B256::ZERO),
        "intent binding"
    );
    endpoint(&c.consensus_rpc)?;
    endpoint(&c.execution_rpc)?;
    Ok(())
}
fn commitment(c: &Config, i: &Intent) -> B256 {
    // Solidity abi.encode: all members of the static Attempt tuple are inline.
    keccak256(
        (
            keccak256("dsmack-coupon-issuance-attempt-v1"),
            U256::from(c.chain_id),
            c.guard_address,
            c.issuer_address,
            c.issuance_policy_hash,
            i.coupon_digest,
            (
                i.recipient_commitment,
                i.accepted_offer_hash,
                i.process_nonce,
            ),
        )
            .abi_encode(),
    )
}
fn consumed_slot(coupon: B256) -> U256 {
    // Exact reviewed guard layout: its only storage variable is mapping at slot 0.
    U256::from_be_bytes(keccak256((coupon, U256::ZERO).abi_encode()).0)
}
fn fresh(timestamp: u64, now_ms: u64, max_age: u64) -> Result<()> {
    let now = now_ms / 1000;
    ensure!(
        timestamp <= now && now - timestamp <= max_age,
        "finalized state stale or future"
    );
    Ok(())
}
fn word(bytes: &[u8]) -> Result<B256> {
    ensure!(bytes.len() == 32, "guard getter encoding");
    Ok(B256::from_slice(bytes))
}

async fn verify(c: &Config, i: &Intent) -> Result<Verdict> {
    validate(c, i)?;
    // No external checkpoint fallback, disk checkpoint override, RPC listener,
    // signer, optimistic reads or caller-supplied 'finalized' boolean.
    let client = EthereumClientBuilder::<ConfigDB>::new()
        .network(Network::Sepolia)
        .consensus_rpc(&c.consensus_rpc)?
        .execution_rpc(&c.execution_rpc)?
        .checkpoint(c.bootstrap_checkpoint)
        .strict_checkpoint_age()
        .build()?;
    let operation = async {
        client.wait_synced().await?;
        let block = client
            .get_block(BlockNumberOrTag::Finalized.into(), false)
            .await?
            .ok_or_else(|| eyre::eyre!("no authenticated finalized head"))?;
        let h = block.header;
        fresh(h.timestamp(), unix_ms()?, c.max_finalized_age_seconds)?;
        let id = h.hash.into();
        let code = client.get_code(c.guard_address, id).await?;
        ensure!(keccak256(&code) == c.guard_code_hash, "guard code differs");
        let get = |name: &str| {
            TransactionRequest::default()
                .to(c.guard_address)
                .input(keccak256(name).as_slice()[..4].to_vec().into())
        };
        let issuer = word(&client.call(&get("issuer()"), id, None).await?)?;
        ensure!(
            issuer.as_slice()[..12] == [0; 12]
                && Address::from_slice(&issuer.as_slice()[12..]) == c.issuer_address,
            "guard issuer differs"
        );
        ensure!(
            word(&client.call(&get("policyHash()"), id, None).await?)? == c.issuance_policy_hash,
            "guard policy differs"
        );
        let slot = consumed_slot(i.coupon_digest);
        let value = client.get_storage_at(c.guard_address, slot, id).await?;
        ensure!(
            value == commitment(c, i),
            "current process attempt not consumed"
        );
        let verified_at_ms = unix_ms()?;
        fresh(h.timestamp(), verified_at_ms, c.max_finalized_age_seconds)?;
        Ok(Verdict {
            version: 1,
            trust_profile: PROFILE,
            upstream_sha: UPSTREAM,
            chain_id: c.chain_id,
            genesis_validators_root: c.genesis_validators_root,
            bootstrap_checkpoint: c.bootstrap_checkpoint,
            finalized_block: FinalizedBlock {
                hash: h.hash,
                number: h.number(),
                timestamp: h.timestamp(),
                state_root: h.state_root(),
                receipts_root: h.receipts_root(),
            },
            verified_at_ms,
            freshness_basis: "local-system-time-assumed",
            guard: Guard {
                address: c.guard_address,
                code_hash: c.guard_code_hash,
                issuer: c.issuer_address,
                policy_hash: c.issuance_policy_hash,
                coupon_digest: i.coupon_digest,
                consumed_commitment: value,
            },
        })
    };
    let result =
        tokio::time::timeout(std::time::Duration::from_secs(c.timeout_seconds), operation).await;
    client.shutdown().await;
    result?
}

#[tokio::main]
async fn main() {
    let result = async {
        let args: Vec<_> = std::env::args().collect();
        if args.len() != 3 || args[1] != "--config" {
            bail!("arguments");
        }
        let config_file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&args[2])?;
        ensure!(
            config_file.metadata()?.is_file(),
            "regular protected configuration required"
        );
        let c: Config = read_json(config_file)?;
        // Current intent arrives through an anonymous pipe. Do not put the
        // process nonce in argv, a retained input file or a replayable receipt.
        let i: Intent = read_json(std::io::stdin().lock())?;
        let verdict = verify(&c, &i).await?;
        println!("{}", serde_json::to_string(&verdict)?);
        Ok::<(), eyre::Report>(())
    }
    .await;
    if result.is_err() {
        eprintln!("Finalized consumption verification failed; no issuance permission granted.");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (Config, Intent) {
        let c = Config {
            version: 1,
            trust_profile: PROFILE.into(),
            chain_id: 11155111,
            genesis_validators_root: Network::Sepolia.to_base_config().chain.genesis_root,
            bootstrap_checkpoint: B256::repeat_byte(1),
            consensus_rpc: "https://beacon.invalid".into(),
            execution_rpc: "https://execution.invalid".into(),
            guard_address: Address::repeat_byte(2),
            guard_code_hash: B256::repeat_byte(3),
            issuer_address: Address::repeat_byte(4),
            issuance_policy_hash: B256::repeat_byte(5),
            max_finalized_age_seconds: 1800,
            timeout_seconds: 30,
        };
        let i = Intent {
            version: 1,
            coupon_digest: B256::repeat_byte(6),
            recipient_commitment: B256::repeat_byte(7),
            accepted_offer_hash: B256::repeat_byte(8),
            process_nonce: B256::repeat_byte(9),
        };
        (c, i)
    }
    #[test]
    fn stale_future_and_boundary() {
        assert!(fresh(100, 100_000, 60).is_ok());
        assert!(fresh(100, 160_000, 60).is_ok());
        assert!(fresh(100, 161_000, 60).is_err());
        assert!(fresh(101, 100_000, 60).is_err());
    }
    #[test]
    fn exact_domain_and_all_intent_members_bind() {
        let (mut c, i) = fixture();
        let expected = commitment(&c, &i);
        // Independent Foundry cast abi-encode + keccak vector for the exact
        // guard ABI (not this implementation's own serialization).
        assert_eq!(
            expected,
            alloy::primitives::b256!(
                "195eac59ad03bd94abee90d845e48b5a73a5a8535e8d8f875291c257ec58d413"
            )
        );
        for n in 0..4 {
            let mut changed = i.clone();
            match n {
                0 => changed.coupon_digest = B256::repeat_byte(10),
                1 => changed.recipient_commitment = B256::repeat_byte(10),
                2 => changed.accepted_offer_hash = B256::repeat_byte(10),
                _ => changed.process_nonce = B256::repeat_byte(10),
            };
            assert_ne!(commitment(&c, &changed), expected);
        }
        c.chain_id += 1;
        assert_ne!(commitment(&c, &i), expected);
        let (mut c, i) = fixture();
        c.guard_address = Address::repeat_byte(10);
        assert_ne!(commitment(&c, &i), expected);
        let (mut c, i) = fixture();
        c.issuer_address = Address::repeat_byte(10);
        assert_ne!(commitment(&c, &i), expected);
        let (mut c, i) = fixture();
        c.issuance_policy_hash = B256::repeat_byte(10);
        assert_ne!(commitment(&c, &i), expected);
    }
    #[test]
    fn network_and_policy_pins_refuse_before_network() {
        let (mut c, i) = fixture();
        validate(&c, &i).unwrap();
        c.chain_id = 84532;
        assert!(validate(&c, &i).is_err());
        let (mut c, i) = fixture();
        c.genesis_validators_root = B256::ZERO;
        assert!(validate(&c, &i).is_err());
        let (mut c, i) = fixture();
        c.bootstrap_checkpoint = B256::ZERO;
        assert!(validate(&c, &i).is_err());
        let (mut c, i) = fixture();
        c.guard_code_hash = B256::ZERO;
        assert!(validate(&c, &i).is_err());
        let (c, mut i) = fixture();
        i.process_nonce = B256::ZERO;
        assert!(validate(&c, &i).is_err());
        assert!(endpoint("http://evil.invalid").is_err());
        assert!(endpoint("https://user:secret@rpc.invalid").is_err());
    }
}
