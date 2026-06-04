//! A program to verify a Base L2 block STF with Ethereum DA in the ZisK zkVM.
//!
//! This binary contains the client program for executing the Base rollup state
//! transition across a range of blocks, which can be used to generate an on-chain
//! validity proof. Depending on the compilation pipeline, it compiles to run
//! either in native mode or in ZisK zkVM mode. In native mode, the data for
//! verifying the batch validity is fetched from RPC, while in zkVM mode, the
//! data is supplied by the host binary to the verifiable program.

#![no_main]
ziskos::entrypoint!(main);

use base_proof_zisk_client_utils::{DefaultWitnessData, ETHDAWitnessExecutor, WitnessData};
use base_proof_zisk_range_utils::RangeProgram;
#[cfg(feature = "tracing-subscriber")]
use base_proof_zisk_range_utils::RangeTracing;
use rkyv::rancor::Error;

fn main() {
    #[cfg(feature = "tracing-subscriber")]
    RangeTracing::setup();

    base_proof::block_on(async move {
        let witness_bytes = ziskos::io::read_input_slice();
        let witness_data = rkyv::from_bytes::<DefaultWitnessData, Error>(&witness_bytes)
            .expect("Failed to deserialize witness data.");

        let (oracle, beacon) = witness_data
            .get_oracle_and_blob_provider()
            .await
            .expect("Failed to load oracle and blob provider");

        RangeProgram::run(ETHDAWitnessExecutor::new(), oracle, beacon).await;
    });
}
