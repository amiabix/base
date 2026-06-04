//! [`PrecompileProvider`] for zkVM-accelerated rollup precompiles.

use alloc::{boxed::Box, string::String};

use alloy_evm::precompiles::PrecompilesMap;
#[cfg(target_os = "zkvm")]
use alloy_evm::precompiles::{DynPrecompile, Precompile};
use alloy_primitives::Address;
use base_common_evm::{BasePrecompiles, BaseSpecId};
use base_common_precompiles::PrecompileCallObserver;
#[cfg(any(test, target_os = "zkvm"))]
use revm::precompile::PrecompileId;
use revm::{
    context::{Cfg, ContextTr},
    handler::PrecompileProvider,
    interpreter::{CallInputs, InterpreterResult},
};

mod custom;
pub use custom::CustomCrypto;

mod factory;
pub use factory::ZkvmBaseEvmFactory;

/// Tracker names for accelerated precompiles.
pub mod cycle_tracker {
    /// Prefix for all precompile cycle tracker keys.
    pub const PREFIX: &str = "precompile-";

    /// Individual tracker names without prefix.
    pub mod names {
        /// BN254 addition.
        pub const BN_ADD: &str = "bn-add";
        /// BN254 scalar multiplication.
        pub const BN_MUL: &str = "bn-mul";
        /// BN254 pairing check.
        pub const BN_PAIR: &str = "bn-pair";
        /// ECDSA recovery.
        pub const EC_RECOVER: &str = "ec-recover";
        /// P-256 signature verification.
        pub const P256_VERIFY: &str = "p256-verify";
        /// KZG point evaluation.
        pub const KZG_EVAL: &str = "kzg-eval";
    }

    /// Full cycle tracker keys.
    pub mod keys {
        /// BN254 addition.
        pub const BN_ADD: &str = "precompile-bn-add";
        /// BN254 scalar multiplication.
        pub const BN_MUL: &str = "precompile-bn-mul";
        /// BN254 pairing check.
        pub const BN_PAIR: &str = "precompile-bn-pair";
        /// ECDSA recovery.
        pub const EC_RECOVER: &str = "precompile-ec-recover";
        /// P-256 signature verification.
        pub const P256_VERIFY: &str = "precompile-p256-verify";
        /// KZG point evaluation.
        pub const KZG_EVAL: &str = "precompile-kzg-eval";
    }
}

#[cfg(any(test, target_os = "zkvm"))]
#[inline]
const fn get_precompile_tracker_name(id: &PrecompileId) -> Option<&'static str> {
    match id {
        PrecompileId::Bn254Add => Some(cycle_tracker::names::BN_ADD),
        PrecompileId::Bn254Mul => Some(cycle_tracker::names::BN_MUL),
        PrecompileId::Bn254Pairing => Some(cycle_tracker::names::BN_PAIR),
        PrecompileId::EcRec => Some(cycle_tracker::names::EC_RECOVER),
        PrecompileId::P256Verify => Some(cycle_tracker::names::P256_VERIFY),
        PrecompileId::KzgPointEvaluation => Some(cycle_tracker::names::KZG_EVAL),
        _ => None,
    }
}

/// `ZisK` cycle-tracker observer for Base-native precompile operations.
#[derive(Debug, Default, Clone, Copy)]
pub struct ZiskCycleObserver;

impl PrecompileCallObserver for ZiskCycleObserver {
    fn start(&self, label: &'static str) {
        let _ = label;
        #[cfg(target_os = "zkvm")]
        println!("cycle-tracker-report-start: {label}");
    }

    fn end(&self, label: &'static str) {
        let _ = label;
        #[cfg(target_os = "zkvm")]
        println!("cycle-tracker-report-end: {label}");
    }
}

/// The zkVM-cycle-tracking precompiles.
#[derive(Debug)]
pub struct BaseZkvmPrecompiles {
    /// The installed Base precompile map, with zkVM wrappers layered on top.
    inner: PrecompilesMap,
    /// The [`BaseSpecId`] of the precompiles.
    spec: BaseSpecId,
    /// Activation registry admin address.
    activation_admin_address: Option<Address>,
}

impl BaseZkvmPrecompiles {
    /// Create a new precompile provider with the given [`BaseSpecId`].
    #[inline]
    pub fn new_with_spec(spec: BaseSpecId) -> Self {
        Self::new_with_spec_and_activation_admin_address(spec, None)
    }

    /// Create a new precompile provider with the given [`BaseSpecId`] and activation admin.
    #[inline]
    pub fn new_with_spec_and_activation_admin_address(
        spec: BaseSpecId,
        activation_admin_address: Option<Address>,
    ) -> Self {
        let inner = Self::installed_precompiles(spec, activation_admin_address);

        Self { inner, spec, activation_admin_address }
    }

    /// Rebuild this provider with an activation admin address.
    #[inline]
    pub fn with_activation_admin_address(self, activation_admin_address: Option<Address>) -> Self {
        Self::new_with_spec_and_activation_admin_address(self.spec, activation_admin_address)
    }

    /// Returns the activation registry admin address.
    pub const fn activation_admin_address(&self) -> Option<Address> {
        self.activation_admin_address
    }

    fn installed_precompiles(
        spec: BaseSpecId,
        activation_admin_address: Option<Address>,
    ) -> PrecompilesMap {
        let mut precompiles = BasePrecompiles::new_with_spec(spec)
            .with_activation_admin_address(activation_admin_address)
            .install_with_observer(ZiskCycleObserver);
        Self::install_cycle_trackers(&mut precompiles);
        precompiles
    }

    #[cfg(target_os = "zkvm")]
    fn install_cycle_trackers(precompiles: &mut PrecompilesMap) {
        precompiles.map_cacheable_precompiles(|_, precompile| {
            let id = precompile.precompile_id().clone();
            if let Some(tracker_name) = get_precompile_tracker_name(&id) {
                DynPrecompile::new(id, move |input| {
                    println!("cycle-tracker-report-start: precompile-{}", tracker_name);
                    let result = precompile.call(input);
                    println!("cycle-tracker-report-end: precompile-{}", tracker_name);
                    result
                })
            } else {
                precompile
            }
        });
    }

    #[cfg(not(target_os = "zkvm"))]
    const fn install_cycle_trackers(_precompiles: &mut PrecompilesMap) {}
}

impl<CTX> PrecompileProvider<CTX> for BaseZkvmPrecompiles
where
    CTX: ContextTr<Cfg: Cfg<Spec = BaseSpecId>>,
    PrecompilesMap: PrecompileProvider<CTX, Output = InterpreterResult>,
{
    type Output = InterpreterResult;

    #[inline]
    fn set_spec(&mut self, spec: <CTX::Cfg as Cfg>::Spec) -> bool {
        if spec == self.spec {
            return false;
        }
        *self =
            Self::new_with_spec_and_activation_admin_address(spec, self.activation_admin_address);
        true
    }

    #[inline]
    fn run(
        &mut self,
        context: &mut CTX,
        inputs: &CallInputs,
    ) -> Result<Option<Self::Output>, String> {
        <PrecompilesMap as PrecompileProvider<CTX>>::run(&mut self.inner, context, inputs)
    }

    #[inline]
    fn warm_addresses(&self) -> Box<impl Iterator<Item = Address>> {
        Box::new(self.inner.addresses().copied())
    }

    #[inline]
    fn contains(&self, address: &Address) -> bool {
        self.inner.get(address).is_some()
    }
}

extern crate alloc;

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use alloy_evm::precompiles::PrecompilesMap;
    use alloy_primitives::{B256, Bytes, U256};
    use base_common_evm::{BaseContext, BaseUpgrade, DefaultBase as _};
    use base_common_precompiles::{
        ActivationRegistryStorage, B20FactoryStorage, B20Variant, PolicyRegistryStorage,
    };
    use revm::{
        Context,
        database::EmptyDB,
        handler::PrecompileProvider,
        interpreter::{CallInput, CallScheme, CallValue, InstructionResult},
    };
    use revm_precompile::secp256r1;

    use super::*;

    type TestContext = BaseContext<EmptyDB>;

    fn create_call_inputs(address: Address, input: Bytes, gas_limit: u64) -> CallInputs {
        CallInputs {
            input: CallInput::Bytes(input),
            gas_limit,
            bytecode_address: address,
            target_address: Address::ZERO,
            caller: Address::ZERO,
            value: CallValue::Transfer(U256::ZERO),
            scheme: CallScheme::Call,
            is_static: false,
            return_memory_offset: 0..0,
            known_bytecode: Default::default(),
            reservoir: 0,
        }
    }

    fn create_test_context() -> TestContext {
        Context::base().with_db(EmptyDB::new())
    }

    #[test]
    fn test_precompile_lookup_uses_bytecode_address() {
        let mut ctx = create_test_context();
        let mut precompiles =
            BaseZkvmPrecompiles::new_with_spec(BaseSpecId::new(BaseUpgrade::Bedrock));

        let sha256_addr = revm::precompile::u64_to_address(2);
        let call_inputs = create_call_inputs(sha256_addr, Bytes::from_static(b"test"), u64::MAX);
        assert_ne!(call_inputs.bytecode_address, call_inputs.target_address);

        let result = precompiles.run(&mut ctx, &call_inputs).unwrap();
        assert!(result.is_some(), "Precompile should be found via bytecode_address");
        let interpreter_result = result.unwrap();
        assert_eq!(interpreter_result.result, InstructionResult::Return);
        assert!(!interpreter_result.output.is_empty());
    }

    #[test]
    fn test_run_nonexistent_precompile() {
        let mut ctx = create_test_context();
        let mut precompiles =
            BaseZkvmPrecompiles::new_with_spec(BaseSpecId::new(BaseUpgrade::Bedrock));

        let fake_addr = Address::from_slice(&[0xFFu8; 20]);
        let call_inputs = create_call_inputs(fake_addr, Bytes::new(), u64::MAX);

        let result = precompiles.run(&mut ctx, &call_inputs).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_run_out_of_gas() {
        let mut ctx = create_test_context();
        let mut precompiles =
            BaseZkvmPrecompiles::new_with_spec(BaseSpecId::new(BaseUpgrade::Bedrock));

        let sha256_addr = revm::precompile::u64_to_address(2);
        let call_inputs = create_call_inputs(sha256_addr, Bytes::from_static(b"test"), 0);

        let result = precompiles.run(&mut ctx, &call_inputs).unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().result, InstructionResult::PrecompileOOG);
    }

    #[test]
    fn test_run_with_shared_buffer_empty() {
        let mut ctx = create_test_context();
        let mut precompiles =
            BaseZkvmPrecompiles::new_with_spec(BaseSpecId::new(BaseUpgrade::Bedrock));

        let sha256_addr = revm::precompile::u64_to_address(2);
        let call_inputs = CallInputs {
            input: CallInput::SharedBuffer(0..0),
            gas_limit: u64::MAX,
            bytecode_address: sha256_addr,
            target_address: Address::ZERO,
            caller: Address::ZERO,
            value: CallValue::Transfer(U256::ZERO),
            scheme: CallScheme::Call,
            is_static: false,
            return_memory_offset: 0..0,
            known_bytecode: Default::default(),
            reservoir: 0,
        };

        let result = precompiles.run(&mut ctx, &call_inputs).unwrap();
        assert!(result.is_some());
    }

    #[test]
    fn test_precompile_tracker_name_bn_add() {
        assert_eq!(
            get_precompile_tracker_name(&PrecompileId::Bn254Add),
            Some(cycle_tracker::names::BN_ADD)
        );
    }

    #[test]
    fn test_precompile_tracker_name_bn_mul() {
        assert_eq!(
            get_precompile_tracker_name(&PrecompileId::Bn254Mul),
            Some(cycle_tracker::names::BN_MUL)
        );
    }

    #[test]
    fn test_precompile_tracker_name_bn_pair() {
        assert_eq!(
            get_precompile_tracker_name(&PrecompileId::Bn254Pairing),
            Some(cycle_tracker::names::BN_PAIR)
        );
    }

    #[test]
    fn test_precompile_tracker_name_ecrecover() {
        assert_eq!(
            get_precompile_tracker_name(&PrecompileId::EcRec),
            Some(cycle_tracker::names::EC_RECOVER)
        );
    }

    #[test]
    fn test_precompile_tracker_name_p256verify() {
        assert_eq!(
            get_precompile_tracker_name(&PrecompileId::P256Verify),
            Some(cycle_tracker::names::P256_VERIFY)
        );
    }

    #[test]
    fn test_precompile_tracker_name_kzg_eval() {
        assert_eq!(
            get_precompile_tracker_name(&PrecompileId::KzgPointEvaluation),
            Some(cycle_tracker::names::KZG_EVAL)
        );
    }

    #[test]
    fn test_unknown_precompile_returns_none() {
        assert_eq!(get_precompile_tracker_name(&PrecompileId::Sha256), None);
        assert_eq!(get_precompile_tracker_name(&PrecompileId::Identity), None);
    }

    #[test]
    fn test_zkvm_precompiles_match_base_evm_precompiles() {
        for spec in BaseUpgrade::VARIANTS.iter().copied().map(BaseSpecId::new) {
            let base_precompiles = BasePrecompiles::new_with_spec(spec).install();
            let zkvm_precompiles = BaseZkvmPrecompiles::new_with_spec(spec);

            let base_addresses: Vec<_> =
                <PrecompilesMap as PrecompileProvider<TestContext>>::warm_addresses(
                    &base_precompiles,
                )
                .collect();
            let zkvm_addresses: Vec<_> =
                <BaseZkvmPrecompiles as PrecompileProvider<TestContext>>::warm_addresses(
                    &zkvm_precompiles,
                )
                .collect();

            assert_eq!(
                zkvm_addresses.len(),
                base_addresses.len(),
                "ZKVM and Base EVM precompile counts must match for {spec:?}",
            );

            for address in &base_addresses {
                assert!(
                    <BaseZkvmPrecompiles as PrecompileProvider<TestContext>>::contains(
                        &zkvm_precompiles,
                        address,
                    ),
                    "ZKVM precompiles missing Base EVM precompile {address:?} for {spec:?}",
                );
            }

            for address in &zkvm_addresses {
                assert!(
                    <PrecompilesMap as PrecompileProvider<TestContext>>::contains(
                        &base_precompiles,
                        address,
                    ),
                    "ZKVM precompiles contain non-Base EVM precompile {address:?} for {spec:?}",
                );
            }
        }
    }

    #[test]
    fn test_zkvm_precompiles_match_beryl_dynamic_installation() {
        let (token_address, _) =
            B20Variant::B20.compute_address(Address::repeat_byte(0x11), B256::repeat_byte(0x22));

        let installed_addresses = [
            B20FactoryStorage::ADDRESS,
            PolicyRegistryStorage::ADDRESS,
            ActivationRegistryStorage::ADDRESS,
            token_address,
        ];

        for (upgrade, expected) in [(BaseUpgrade::Azul, false), (BaseUpgrade::Beryl, true)] {
            let spec = BaseSpecId::new(upgrade);
            let base_precompiles = BasePrecompiles::new_with_spec(spec).install();
            let zkvm_precompiles = BaseZkvmPrecompiles::new_with_spec(spec);

            for address in installed_addresses {
                assert_eq!(
                    base_precompiles.get(&address).is_some(),
                    expected,
                    "Base EVM install state changed for {address:?} at {upgrade:?}",
                );
                assert_eq!(
                    <BaseZkvmPrecompiles as PrecompileProvider<TestContext>>::contains(
                        &zkvm_precompiles,
                        &address,
                    ),
                    expected,
                    "ZKVM install state diverged for {address:?} at {upgrade:?}",
                );
            }
        }
    }

    #[test]
    fn test_tracker_keys_match_expected_format() {
        let expected_keys = [
            cycle_tracker::keys::BN_ADD,
            cycle_tracker::keys::BN_MUL,
            cycle_tracker::keys::BN_PAIR,
            cycle_tracker::keys::EC_RECOVER,
            cycle_tracker::keys::P256_VERIFY,
            cycle_tracker::keys::KZG_EVAL,
        ];

        for key in &expected_keys {
            assert!(
                key.starts_with(cycle_tracker::PREFIX),
                "Key '{}' should start with '{}'",
                key,
                cycle_tracker::PREFIX
            );
            assert!(!key.contains(' '), "Key '{key}' contains spaces");
            assert!(
                !key[cycle_tracker::PREFIX.len()..].contains('_'),
                "Key '{key}' contains underscores (should use dashes)"
            );
        }
    }

    #[test]
    fn test_azul_uses_osaka_p256verify() {
        let p256_addr = *secp256r1::P256VERIFY.address();

        let jovian_set = BasePrecompiles::new_with_spec(BaseSpecId::new(BaseUpgrade::Jovian));
        let azul_set = BasePrecompiles::new_with_spec(BaseSpecId::new(BaseUpgrade::Azul));

        let jovian_p256 =
            jovian_set.precompiles().get(&p256_addr).expect("JOVIAN must have P256VERIFY");
        let azul_p256 = azul_set.precompiles().get(&p256_addr).expect("AZUL must have P256VERIFY");

        assert!(
            jovian_p256.execute(&[], 5_000, 0).is_ok(),
            "JOVIAN P256VERIFY must succeed with 5,000 gas (legacy pricing, 3,450 base fee)",
        );

        let azul_result = azul_p256.execute(&[], 5_000, 0);
        assert!(
            matches!(&azul_result, Ok(output) if output.halt_reason().is_some()),
            "AZUL P256VERIFY must fail with 5,000 gas (Osaka pricing, 6,900 base fee)",
        );
    }

    #[test]
    fn test_names_and_keys_are_consistent() {
        assert_eq!(
            cycle_tracker::keys::BN_ADD,
            format!("{}{}", cycle_tracker::PREFIX, cycle_tracker::names::BN_ADD)
        );
        assert_eq!(
            cycle_tracker::keys::BN_MUL,
            format!("{}{}", cycle_tracker::PREFIX, cycle_tracker::names::BN_MUL)
        );
        assert_eq!(
            cycle_tracker::keys::BN_PAIR,
            format!("{}{}", cycle_tracker::PREFIX, cycle_tracker::names::BN_PAIR)
        );
        assert_eq!(
            cycle_tracker::keys::EC_RECOVER,
            format!("{}{}", cycle_tracker::PREFIX, cycle_tracker::names::EC_RECOVER)
        );
        assert_eq!(
            cycle_tracker::keys::P256_VERIFY,
            format!("{}{}", cycle_tracker::PREFIX, cycle_tracker::names::P256_VERIFY)
        );
        assert_eq!(
            cycle_tracker::keys::KZG_EVAL,
            format!("{}{}", cycle_tracker::PREFIX, cycle_tracker::names::KZG_EVAL)
        );
    }
}
