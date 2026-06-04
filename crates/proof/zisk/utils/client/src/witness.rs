//! Witness data, preimage storage, and block-execution glue for the `ZisK` guests.

mod executor {
    //! Host/guest-shared trait for witness-driven derivation and execution.

    use std::{fmt::Debug, sync::Arc};

    use alloy_genesis::ChainConfig;
    use alloy_primitives::Sealed;
    use anyhow::{Result, anyhow};
    use async_trait::async_trait;
    use base_common_genesis::RollupConfig;
    use base_consensus_derive::{
        BlobProvider, ChainProvider, DataAvailabilityProvider, L2ChainProvider, Pipeline,
        SignalReceiver,
    };
    use base_proof::{
        BaseExecutor, BootInfo, OracleL1ChainProvider, OracleL2ChainProvider, OraclePipeline,
        new_oracle_pipeline_cursor,
    };
    use base_proof_driver::{Driver, DriverPipeline, PipelineCursor};
    use base_proof_executor::TrieDBProvider;
    use base_proof_preimage::{CommsClient, FlushableCache};
    use spin::RwLock;
    use tracing::info;

    use crate::client::{advance_to_target, fetch_safe_head_hash};
    use crate::precompiles::{CustomCrypto, ZkvmBaseEvmFactory};

    /// Pipeline inputs returned by [`get_inputs_for_pipeline`].
    pub type PipelineInputs<O> =
        (Arc<RwLock<PipelineCursor>>, OracleL1ChainProvider<O>, OracleL2ChainProvider<O>);

    /// Build derivation-pipeline inputs from the supplied preimage store.
    pub async fn get_inputs_for_pipeline<O>(
        oracle: Arc<O>,
    ) -> Result<(BootInfo, PipelineInputs<O>, u64)>
    where
        O: CommsClient + FlushableCache + Send + Sync + Debug,
    {
        let boot = BootInfo::load(oracle.as_ref())
            .await
            .map_err(|error| anyhow!("failed to load boot info: {error:?}"))?;
        let boot_clone = boot.clone();

        let rollup_config = Arc::new(boot.rollup_config);
        let safe_head_hash =
            fetch_safe_head_hash(oracle.as_ref(), boot.agreed_l2_output_root).await?;

        let mut l1_provider = OracleL1ChainProvider::new(boot.l1_head, Arc::clone(&oracle));
        let mut l2_provider = OracleL2ChainProvider::new(
            safe_head_hash,
            Arc::clone(&rollup_config),
            Arc::clone(&oracle),
        );

        let safe_head = l2_provider
            .header_by_hash(safe_head_hash)
            .map(|header| Sealed::new_unchecked(header, safe_head_hash))?;
        let safe_head_number = safe_head.number;

        if boot.claimed_l2_block_number < safe_head.number {
            return Err(anyhow!(
                "claimed L2 block number {claimed} is less than safe head {safe}",
                claimed = boot.claimed_l2_block_number,
                safe = safe_head.number
            ));
        }

        let cursor = new_oracle_pipeline_cursor(
            rollup_config.as_ref(),
            safe_head,
            boot.agreed_l2_output_root,
            &mut l1_provider,
            &mut l2_provider,
        )
        .await?;
        l2_provider.set_cursor(Arc::clone(&cursor));

        Ok((boot_clone, (cursor, l1_provider, l2_provider), safe_head_number))
    }

    /// Constructs a derivation pipeline and executes block derivation.
    #[async_trait]
    pub trait WitnessExecutor {
        /// Oracle client.
        type O: CommsClient + FlushableCache + Send + Sync + Debug;
        /// Blob provider.
        type B: BlobProvider + Send + Sync + Debug + Clone;
        /// L1 chain data provider.
        type L1: ChainProvider + Send + Sync + Debug + Clone;
        /// L2 chain data provider.
        type L2: L2ChainProvider + Send + Sync + Debug + Clone;
        /// Data availability provider.
        type DA: DataAvailabilityProvider + Send + Sync + Debug + Clone;

        /// Build the derivation pipeline from the given providers.
        #[allow(clippy::too_many_arguments)]
        async fn create_pipeline(
            &self,
            rollup_config: Arc<RollupConfig>,
            l1_config: Arc<ChainConfig>,
            cursor: Arc<RwLock<PipelineCursor>>,
            oracle: Arc<Self::O>,
            beacon: Self::B,
            l1_provider: Self::L1,
            l2_provider: Self::L2,
        ) -> Result<OraclePipeline<Self::O, Self::L1, Self::L2, Self::DA>>;

        /// Run derivation and block execution to produce the proven boot info and derived L2 block.
        async fn run<O, DP, P>(
            &self,
            boot: BootInfo,
            pipeline: DP,
            cursor: Arc<RwLock<PipelineCursor>>,
            l2_provider: OracleL2ChainProvider<O>,
        ) -> Result<(BootInfo, u64, Vec<alloy_primitives::B256>)>
        where
            O: CommsClient + FlushableCache + Send + Sync + Debug,
            DP: DriverPipeline<P> + Send + Sync + Debug,
            P: Pipeline + SignalReceiver + Send + Sync + Debug,
        {
            revm::precompile::install_crypto(CustomCrypto);

            let boot_clone = boot.clone();
            let activation_admin_address = boot.activation_admin_address;
            let intermediate_block_interval = boot.intermediate_block_interval.max(1);
            let rollup_config = Arc::new(boot.rollup_config);

            let executor = BaseExecutor::new(
                rollup_config.as_ref(),
                l2_provider.clone(),
                l2_provider,
                ZkvmBaseEvmFactory::new_with_activation_admin_address(activation_admin_address),
                None,
            );
            let mut driver = Driver::new(cursor, executor, pipeline);

            #[cfg(target_os = "zkvm")]
            println!("cycle-tracker-report-start: block-execution-and-derivation");
            let (safe_head, output_root, intermediate_roots) = advance_to_target(
                &mut driver,
                rollup_config.as_ref(),
                Some(boot.claimed_l2_block_number),
                intermediate_block_interval,
            )
            .await?;
            #[cfg(target_os = "zkvm")]
            println!("cycle-tracker-report-end: block-execution-and-derivation");

            let derived_l2_block_number = safe_head.block_info.number;
            ensure_derived_block_matches_claim(
                derived_l2_block_number,
                boot.claimed_l2_block_number,
            )?;

            if output_root != boot.claimed_l2_output_root {
                return Err(anyhow!(
                    "failed to validate L2 block #{number} with claimed output root {claimed_output_root}; got {output_root}",
                    number = derived_l2_block_number,
                    output_root = output_root,
                    claimed_output_root = boot.claimed_l2_output_root,
                ));
            }

            info!(
                target: "client",
                block_number = derived_l2_block_number,
                output_root = %output_root,
                "successfully validated L2 block"
            );

            #[cfg(target_os = "zkvm")]
            {
                std::mem::forget(driver);
                std::mem::forget(rollup_config);
            }

            Ok((boot_clone, derived_l2_block_number, intermediate_roots))
        }
    }

    /// Ensures the derived L2 safe-head block number matches the boot's claimed L2 block number.
    pub fn ensure_derived_block_matches_claim(
        safe_head_number: u64,
        claimed_block_number: u64,
    ) -> Result<()> {
        if safe_head_number != claimed_block_number {
            return Err(anyhow!(
                "derived safe head L2 block #{safe_head_number} does not match claimed L2 block number #{claimed_block_number}",
            ));
        }
        Ok(())
    }
}

mod preimage_store {
    //! In-memory preimage oracle for the zkVM.

    use std::collections::{HashMap, hash_map::Entry};

    use alloy_primitives::keccak256;
    use async_trait::async_trait;
    use base_proof_preimage::{
        FlushableCache, HintWriterClient, PreimageKey, PreimageKeyType, PreimageOracleClient,
        errors::{PreimageOracleError, PreimageOracleResult},
    };
    use serde::{Deserialize, Serialize};
    use sha2::Digest;

    /// In-memory store of preimage key-value pairs for the zkVM oracle.
    #[derive(
        Clone,
        Debug,
        Default,
        Serialize,
        Deserialize,
        rkyv::Serialize,
        rkyv::Archive,
        rkyv::Deserialize,
    )]
    pub struct PreimageStore {
        /// Map of preimage keys to their values.
        #[serde(with = "preimage_map_serde")]
        pub preimage_map: HashMap<PreimageKey, Vec<u8>>,
    }

    mod preimage_map_serde {
        use serde::{
            de::Deserializer,
            ser::{SerializeSeq, Serializer},
        };

        use super::{Deserialize, HashMap, PreimageKey};

        pub(super) fn serialize<S: Serializer>(
            map: &HashMap<PreimageKey, Vec<u8>>,
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            let mut seq = serializer.serialize_seq(Some(map.len()))?;
            for (key, value) in map {
                seq.serialize_element(&(key, value))?;
            }
            seq.end()
        }

        pub(super) fn deserialize<'de, D: Deserializer<'de>>(
            deserializer: D,
        ) -> Result<HashMap<PreimageKey, Vec<u8>>, D::Error> {
            let pairs: Vec<(PreimageKey, Vec<u8>)> = Deserialize::deserialize(deserializer)?;
            Ok(pairs.into_iter().collect())
        }
    }

    impl PreimageStore {
        /// Validate all stored preimages against their key hashes.
        pub fn check_preimages(&self) -> PreimageOracleResult<()> {
            for (key, value) in &self.preimage_map {
                check_preimage(key, value)?;
            }
            Ok(())
        }

        /// Insert a preimage, rejecting overwrites with different values.
        pub fn save_preimage(
            &mut self,
            key: PreimageKey,
            value: Vec<u8>,
        ) -> PreimageOracleResult<()> {
            check_preimage(&key, &value)?;

            match self.preimage_map.entry(key) {
                Entry::Vacant(entry) => {
                    entry.insert(value);
                }
                Entry::Occupied(entry) => {
                    if entry.get() != &value {
                        return Err(PreimageOracleError::Other("cannot overwrite key".to_string()));
                    }
                }
            };

            Ok(())
        }
    }

    /// Check that the preimage matches the expected hash.
    pub fn check_preimage(key: &PreimageKey, value: &[u8]) -> PreimageOracleResult<()> {
        if let Some(expected_hash) = match key.key_type() {
            PreimageKeyType::Keccak256 => Some(keccak256(value).0),
            PreimageKeyType::Sha256 => Some(sha2::Sha256::digest(value).into()),
            PreimageKeyType::Local | PreimageKeyType::GlobalGeneric => None,
            PreimageKeyType::Precompile => {
                return Err(PreimageOracleError::Other(
                    "precompile keys are not supported".to_string(),
                ));
            }
            PreimageKeyType::Blob => unreachable!("blob keys are validated by the blob witness"),
        } && key != &PreimageKey::new(expected_hash, key.key_type())
        {
            return Err(PreimageOracleError::InvalidPreimageKey);
        }
        Ok(())
    }

    #[async_trait]
    impl HintWriterClient for PreimageStore {
        async fn write(&self, _hint: &str) -> PreimageOracleResult<()> {
            Ok(())
        }
    }

    #[async_trait]
    impl PreimageOracleClient for PreimageStore {
        async fn get(&self, key: PreimageKey) -> PreimageOracleResult<Vec<u8>> {
            let Some(value) = self.preimage_map.get(&key) else {
                return Err(PreimageOracleError::InvalidPreimageKey);
            };
            Ok(value.clone())
        }

        async fn get_exact(&self, key: PreimageKey, buf: &mut [u8]) -> PreimageOracleResult<()> {
            buf.copy_from_slice(&self.get(key).await?);
            Ok(())
        }
    }

    impl FlushableCache for PreimageStore {
        fn flush(&self) {}
    }
}

pub use executor::{
    PipelineInputs, WitnessExecutor, ensure_derived_block_matches_claim, get_inputs_for_pipeline,
};
pub use preimage_store::{PreimageStore, check_preimage};

use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::{BlobStore, boot::BootInfoStruct};

/// Bytes per EIP-4844 blob.
pub const BYTES_PER_BLOB: usize = 131_072;

/// KZG commitment/proof bytes.
#[derive(
    Clone, Debug, Serialize, Deserialize, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize,
)]
pub struct KzgBytes48(#[serde(with = "serde_arrays")] pub [u8; 48]);

impl KzgBytes48 {
    /// Borrow as raw bytes.
    pub const fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }
}

/// EIP-4844 blob bytes.
#[derive(
    Clone, Debug, Serialize, Deserialize, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize,
)]
pub struct KzgBlob(#[serde(with = "serde_arrays")] pub [u8; BYTES_PER_BLOB]);

/// Witness data that can be split into a preimage store and blob data.
#[async_trait]
pub trait WitnessData: Sized {
    /// Creates witness data from the given preimage store and blob data.
    fn from_parts(preimage_store: PreimageStore, blob_data: BlobData) -> Self;

    /// Consumes the witness data to extract its core components.
    fn into_parts(self) -> (PreimageStore, BlobData);

    /// Gets the oracle and blob provider from the witness data.
    async fn get_oracle_and_blob_provider(self) -> Result<(Arc<PreimageStore>, BlobStore)> {
        let (owned_preimage_store, owned_blob_data) = self.into_parts();

        println!("cycle-tracker-report-start: oracle-verify");
        owned_preimage_store.check_preimages().expect("failed to validate preimages");
        println!("cycle-tracker-report-end: oracle-verify");

        let oracle = Arc::new(owned_preimage_store);

        println!("cycle-tracker-report-start: blob-verification");
        let beacon = BlobStore::try_from(owned_blob_data)?;
        println!("cycle-tracker-report-end: blob-verification");

        Ok((oracle, beacon))
    }
}

/// Default [`WitnessData`] backed by rkyv serialization.
#[derive(Clone, Debug, Default, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct DefaultWitnessData {
    /// Preimage oracle contents.
    pub preimage_store: PreimageStore,
    /// EIP-4844 blob data with KZG commitments and proofs.
    pub blob_data: BlobData,
}

#[async_trait]
impl WitnessData for DefaultWitnessData {
    fn from_parts(preimage_store: PreimageStore, blob_data: BlobData) -> Self {
        Self { preimage_store, blob_data }
    }

    fn into_parts(self) -> (PreimageStore, BlobData) {
        (self.preimage_store, self.blob_data)
    }
}

impl DefaultWitnessData {
    /// Re-execute the collected witness and return the range output it proves.
    pub async fn derive_boot_info(&self) -> Result<BootInfoStruct> {
        let (oracle, beacon) = self.clone().get_oracle_and_blob_provider().await?;
        let (boot_info, input, l2_pre_block_number) =
            get_inputs_for_pipeline(Arc::clone(&oracle)).await?;
        let (cursor, l1_provider, l2_provider) = input;
        let rollup_config = Arc::new(boot_info.rollup_config.clone());
        let l1_config = Arc::new(boot_info.l1_config.clone());
        let executor = crate::executor::ETHDAWitnessExecutor::<PreimageStore, BlobStore>::new();

        let pipeline = executor
            .create_pipeline(
                rollup_config,
                l1_config,
                Arc::clone(&cursor),
                oracle,
                beacon,
                l1_provider,
                l2_provider.clone(),
            )
            .await?;
        let (boot_info, l2_block_number, intermediate_roots) =
            executor.run(boot_info, pipeline, cursor, l2_provider).await?;

        Ok(BootInfoStruct::new(boot_info, l2_pre_block_number, l2_block_number, intermediate_roots))
    }
}

/// EIP-4844 blob data with commitments and KZG proofs.
#[derive(
    Clone, Debug, Default, Serialize, Deserialize, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize,
)]
pub struct BlobData {
    /// Raw blobs.
    pub blobs: Vec<KzgBlob>,
    /// KZG commitments.
    pub commitments: Vec<KzgBytes48>,
    /// KZG proofs.
    pub proofs: Vec<KzgBytes48>,
}
