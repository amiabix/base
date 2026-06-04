use alloc::sync::Arc;

use base_proof::{OracleL1ChainProvider, OracleL2ChainProvider};
use base_proof_zisk_client_utils::{
    BlobStore, BootInfoStruct, PreimageStore, WitnessExecutor, boot_info_commitment,
    get_inputs_for_pipeline,
};

/// Range guest execution entry point.
#[derive(Debug, Clone, Copy)]
pub struct RangeProgram;

impl RangeProgram {
    /// Run the range program and commit the range output digest as public
    /// values.
    pub async fn run<E>(executor: E, oracle: Arc<PreimageStore>, beacon: BlobStore)
    where
        E: WitnessExecutor<
                O = PreimageStore,
                B = BlobStore,
                L1 = OracleL1ChainProvider<PreimageStore>,
                L2 = OracleL2ChainProvider<PreimageStore>,
            > + Send
            + Sync,
    {
        let (boot_info, input, l2_pre_block_number) =
            get_inputs_for_pipeline(Arc::clone(&oracle))
                .await
                .expect("failed to load range guest pipeline inputs");
        let (cursor, l1_provider, l2_provider) = input;
        let rollup_config = Arc::new(boot_info.rollup_config.clone());
        let l1_config = Arc::new(boot_info.l1_config.clone());

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
            .await
            .expect("failed to create range guest derivation pipeline");

        let (boot_info, l2_block_number, intermediate_roots) =
            executor
                .run(boot_info, pipeline, cursor, l2_provider)
                .await
                .expect("failed to execute range guest derivation pipeline");

        let committed = BootInfoStruct::new(
            boot_info,
            l2_pre_block_number,
            l2_block_number,
            intermediate_roots,
        );
        let digest = boot_info_commitment(&committed);
        ziskos::io::commit_slice(digest.as_ref());
    }
}
