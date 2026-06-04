//! Crypto provider for `ZisK` guest execution.
//!
//! On the `riscv64ima-zisk-zkvm-elf` target, crypto operations dispatch to
//! ZisK's zkvm-standards C accelerator interface exported by `zkvm-interface`
//! (`zkvm_accelerators.h`). On native targets the calls fall through to
//! `revm::precompile::DefaultCrypto`, so the same provider is usable from
//! host unit tests.
//!
//! Reference: <https://github.com/eth-act/zkvm-standards/tree/main/standards/c-interface-accelerators>

use revm::precompile::{Crypto, PrecompileHalt};
#[cfg(all(target_os = "zkvm", target_vendor = "zisk"))]
use zkvm_interface::*;

/// Crypto provider backed by ZisK's zkvm-standards accelerator interface.
#[derive(Debug, Default, Clone, Copy)]
pub struct CustomCrypto;

impl Crypto for CustomCrypto {
    #[inline]
    fn sha256(&self, input: &[u8]) -> [u8; 32] {
        #[cfg(all(target_os = "zkvm", target_vendor = "zisk"))]
        {
            let mut output = zkvm_sha256_hash { data: [0u8; 32] };
            unsafe { zkvm_sha256(input.as_ptr(), input.len(), &mut output) };
            output.data
        }

        #[cfg(not(all(target_os = "zkvm", target_vendor = "zisk")))]
        {
            use sha2::Digest;
            sha2::Sha256::digest(input).into()
        }
    }

    #[inline]
    fn blake2_compress(&self, rounds: u32, h: &mut [u64; 8], m: &[u64; 16], t: &[u64; 2], f: bool) {
        #[cfg(all(target_os = "zkvm", target_vendor = "zisk"))]
        {
            unsafe {
                zkvm_blake2f(
                    rounds,
                    h.as_mut_ptr() as *mut zkvm_blake2f_state,
                    m.as_ptr() as *const zkvm_blake2f_message,
                    t.as_ptr() as *const zkvm_blake2f_offset,
                    f as u8,
                );
            }
        }

        #[cfg(not(all(target_os = "zkvm", target_vendor = "zisk")))]
        {
            revm::precompile::DefaultCrypto.blake2_compress(rounds, h, m, t, f);
        }
    }

    #[inline]
    fn ripemd160(&self, input: &[u8]) -> [u8; 32] {
        #[cfg(all(target_os = "zkvm", target_vendor = "zisk"))]
        {
            let mut output = zkvm_ripemd160_hash { data: [0u8; 32] };
            unsafe { zkvm_ripemd160(input.as_ptr(), input.len(), &mut output) };
            output.data
        }

        #[cfg(not(all(target_os = "zkvm", target_vendor = "zisk")))]
        {
            revm::precompile::DefaultCrypto.ripemd160(input)
        }
    }

    #[inline]
    fn bn254_g1_add(&self, p1: &[u8], p2: &[u8]) -> Result<[u8; 64], PrecompileHalt> {
        #[cfg(all(target_os = "zkvm", target_vendor = "zisk"))]
        {
            let mut result = zkvm_bn254_g1_point { data: [0u8; 64] };
            let ret = unsafe {
                zkvm_bn254_g1_add(
                    p1.as_ptr() as *const zkvm_bn254_g1_point,
                    p2.as_ptr() as *const zkvm_bn254_g1_point,
                    &mut result,
                )
            };
            if ret == zkvm_status_ZKVM_EOK {
                Ok(result.data)
            } else {
                Err(PrecompileHalt::Bn254FieldPointNotAMember)
            }
        }

        #[cfg(not(all(target_os = "zkvm", target_vendor = "zisk")))]
        {
            revm::precompile::DefaultCrypto.bn254_g1_add(p1, p2)
        }
    }

    #[inline]
    fn bn254_g1_mul(&self, point: &[u8], scalar: &[u8]) -> Result<[u8; 64], PrecompileHalt> {
        #[cfg(all(target_os = "zkvm", target_vendor = "zisk"))]
        {
            let mut result = zkvm_bn254_g1_point { data: [0u8; 64] };
            let ret = unsafe {
                zkvm_bn254_g1_mul(
                    point.as_ptr() as *const zkvm_bn254_g1_point,
                    scalar.as_ptr() as *const zkvm_bn254_scalar,
                    &mut result,
                )
            };
            if ret == zkvm_status_ZKVM_EOK {
                Ok(result.data)
            } else {
                Err(PrecompileHalt::Bn254FieldPointNotAMember)
            }
        }

        #[cfg(not(all(target_os = "zkvm", target_vendor = "zisk")))]
        {
            revm::precompile::DefaultCrypto.bn254_g1_mul(point, scalar)
        }
    }

    #[inline]
    fn bn254_pairing_check(&self, pairs: &[(&[u8], &[u8])]) -> Result<bool, PrecompileHalt> {
        #[cfg(all(target_os = "zkvm", target_vendor = "zisk"))]
        {
            let mut pairs_bytes = Vec::new();
            for (g1, g2) in pairs {
                pairs_bytes.extend_from_slice(g1);
                pairs_bytes.extend_from_slice(g2);
            }
            let mut verified = false;
            let ret = unsafe {
                zkvm_bn254_pairing(
                    pairs_bytes.as_ptr() as *const zkvm_bn254_pairing_pair,
                    pairs.len(),
                    &mut verified,
                )
            };
            if ret == zkvm_status_ZKVM_EOK {
                Ok(verified)
            } else {
                Err(PrecompileHalt::other("bn254_pairing failed"))
            }
        }

        #[cfg(not(all(target_os = "zkvm", target_vendor = "zisk")))]
        {
            revm::precompile::DefaultCrypto.bn254_pairing_check(pairs)
        }
    }

    #[inline]
    fn secp256k1_ecrecover(
        &self,
        sig: &[u8; 64],
        recid: u8,
        msg: &[u8; 32],
    ) -> Result<[u8; 32], PrecompileHalt> {
        #[cfg(all(target_os = "zkvm", target_vendor = "zisk"))]
        {
            // zkvm_secp256k1_ecrecover returns 64-byte uncompressed pubkey (x || y),
            // not an address. Caller wants keccak256(pubkey)[12..32] left-padded.
            let mut pubkey = zkvm_secp256k1_pubkey { data: [0u8; 64] };
            let ret = unsafe {
                zkvm_secp256k1_ecrecover(
                    msg.as_ptr() as *const zkvm_secp256k1_hash,
                    sig.as_ptr() as *const zkvm_secp256k1_signature,
                    recid,
                    &mut pubkey,
                )
            };
            if ret != zkvm_status_ZKVM_EOK {
                return Err(PrecompileHalt::Secp256k1RecoverFailed);
            }
            let hash = alloy_primitives::keccak256(pubkey.data);
            let mut result = [0u8; 32];
            result[12..32].copy_from_slice(&hash[12..32]);
            Ok(result)
        }

        #[cfg(not(all(target_os = "zkvm", target_vendor = "zisk")))]
        {
            revm::precompile::DefaultCrypto.secp256k1_ecrecover(sig, recid, msg)
        }
    }

    #[inline]
    fn modexp(&self, base: &[u8], exp: &[u8], modulus: &[u8]) -> Result<Vec<u8>, PrecompileHalt> {
        #[cfg(all(target_os = "zkvm", target_vendor = "zisk"))]
        {
            let mut result = vec![0u8; modulus.len()];
            let ret = unsafe {
                zkvm_modexp(
                    base.as_ptr(),
                    base.len(),
                    exp.as_ptr(),
                    exp.len(),
                    modulus.as_ptr(),
                    modulus.len(),
                    result.as_mut_ptr(),
                )
            };
            if ret == zkvm_status_ZKVM_EOK {
                Ok(result)
            } else {
                Err(PrecompileHalt::other("modexp failed"))
            }
        }

        #[cfg(not(all(target_os = "zkvm", target_vendor = "zisk")))]
        {
            revm::precompile::DefaultCrypto.modexp(base, exp, modulus)
        }
    }

    #[inline]
    fn secp256r1_verify_signature(&self, msg: &[u8; 32], sig: &[u8; 64], pk: &[u8; 64]) -> bool {
        #[cfg(all(target_os = "zkvm", target_vendor = "zisk"))]
        {
            let mut verified = false;
            let ret = unsafe {
                zkvm_secp256r1_verify(
                    msg.as_ptr() as *const zkvm_secp256r1_hash,
                    sig.as_ptr() as *const zkvm_secp256r1_signature,
                    pk.as_ptr() as *const zkvm_secp256r1_pubkey,
                    &mut verified,
                )
            };
            ret == zkvm_status_ZKVM_EOK && verified
        }

        #[cfg(not(all(target_os = "zkvm", target_vendor = "zisk")))]
        {
            revm::precompile::DefaultCrypto.secp256r1_verify_signature(msg, sig, pk)
        }
    }

    #[inline]
    fn verify_kzg_proof(
        &self,
        z: &[u8; 32],
        y: &[u8; 32],
        commitment: &[u8; 48],
        proof: &[u8; 48],
    ) -> Result<(), PrecompileHalt> {
        #[cfg(all(target_os = "zkvm", target_vendor = "zisk"))]
        {
            let mut verified = false;
            // ZisK ABI orders commitment first, then evaluation point and value.
            let ret = unsafe {
                zkvm_kzg_point_eval(
                    commitment.as_ptr() as *const zkvm_kzg_commitment,
                    z.as_ptr() as *const zkvm_kzg_field_element,
                    y.as_ptr() as *const zkvm_kzg_field_element,
                    proof.as_ptr() as *const zkvm_kzg_proof,
                    &mut verified,
                )
            };
            if ret == zkvm_status_ZKVM_EOK && verified {
                Ok(())
            } else {
                Err(PrecompileHalt::BlobVerifyKzgProofFailed)
            }
        }

        #[cfg(not(all(target_os = "zkvm", target_vendor = "zisk")))]
        {
            revm::precompile::DefaultCrypto.verify_kzg_proof(z, y, commitment, proof)
        }
    }

    fn bls12_381_g1_add(
        &self,
        a: ([u8; 48], [u8; 48]),
        b: ([u8; 48], [u8; 48]),
    ) -> Result<[u8; 96], PrecompileHalt> {
        #[cfg(all(target_os = "zkvm", target_vendor = "zisk"))]
        {
            let mut a_bytes = [0u8; 96];
            a_bytes[..48].copy_from_slice(&a.0);
            a_bytes[48..].copy_from_slice(&a.1);

            let mut b_bytes = [0u8; 96];
            b_bytes[..48].copy_from_slice(&b.0);
            b_bytes[48..].copy_from_slice(&b.1);

            let mut result = zkvm_bls12_381_g1_point { data: [0u8; 96] };
            let ret = unsafe {
                zkvm_bls12_g1_add(
                    a_bytes.as_ptr() as *const zkvm_bls12_381_g1_point,
                    b_bytes.as_ptr() as *const zkvm_bls12_381_g1_point,
                    &mut result,
                )
            };
            if ret == zkvm_status_ZKVM_EOK {
                Ok(result.data)
            } else {
                Err(PrecompileHalt::Bls12381G1NotOnCurve)
            }
        }

        #[cfg(not(all(target_os = "zkvm", target_vendor = "zisk")))]
        {
            revm::precompile::DefaultCrypto.bls12_381_g1_add(a, b)
        }
    }

    fn bls12_381_g1_msm(
        &self,
        pairs: &mut dyn Iterator<Item = Result<(([u8; 48], [u8; 48]), [u8; 32]), PrecompileHalt>>,
    ) -> Result<[u8; 96], PrecompileHalt> {
        #[cfg(all(target_os = "zkvm", target_vendor = "zisk"))]
        {
            let mut pairs_bytes = Vec::new();
            let mut num_pairs = 0usize;
            for pair in pairs {
                let (point, scalar) = pair?;
                pairs_bytes.extend_from_slice(&point.0);
                pairs_bytes.extend_from_slice(&point.1);
                pairs_bytes.extend_from_slice(&scalar);
                num_pairs += 1;
            }
            let mut result = zkvm_bls12_381_g1_point { data: [0u8; 96] };
            let ret = unsafe {
                zkvm_bls12_g1_msm(
                    pairs_bytes.as_ptr() as *const zkvm_bls12_381_g1_msm_pair,
                    num_pairs,
                    &mut result,
                )
            };
            if ret == zkvm_status_ZKVM_EOK {
                Ok(result.data)
            } else {
                Err(PrecompileHalt::other("bls12_381_g1_msm failed"))
            }
        }

        #[cfg(not(all(target_os = "zkvm", target_vendor = "zisk")))]
        {
            revm::precompile::DefaultCrypto.bls12_381_g1_msm(pairs)
        }
    }

    fn bls12_381_g2_add(
        &self,
        a: ([u8; 48], [u8; 48], [u8; 48], [u8; 48]),
        b: ([u8; 48], [u8; 48], [u8; 48], [u8; 48]),
    ) -> Result<[u8; 192], PrecompileHalt> {
        #[cfg(all(target_os = "zkvm", target_vendor = "zisk"))]
        {
            let mut a_bytes = [0u8; 192];
            a_bytes[..48].copy_from_slice(&a.0);
            a_bytes[48..96].copy_from_slice(&a.1);
            a_bytes[96..144].copy_from_slice(&a.2);
            a_bytes[144..].copy_from_slice(&a.3);

            let mut b_bytes = [0u8; 192];
            b_bytes[..48].copy_from_slice(&b.0);
            b_bytes[48..96].copy_from_slice(&b.1);
            b_bytes[96..144].copy_from_slice(&b.2);
            b_bytes[144..].copy_from_slice(&b.3);

            let mut result = zkvm_bls12_381_g2_point { data: [0u8; 192] };
            let ret = unsafe {
                zkvm_bls12_g2_add(
                    a_bytes.as_ptr() as *const zkvm_bls12_381_g2_point,
                    b_bytes.as_ptr() as *const zkvm_bls12_381_g2_point,
                    &mut result,
                )
            };
            if ret == zkvm_status_ZKVM_EOK {
                Ok(result.data)
            } else {
                Err(PrecompileHalt::Bls12381G2NotOnCurve)
            }
        }

        #[cfg(not(all(target_os = "zkvm", target_vendor = "zisk")))]
        {
            revm::precompile::DefaultCrypto.bls12_381_g2_add(a, b)
        }
    }

    fn bls12_381_g2_msm(
        &self,
        pairs: &mut dyn Iterator<
            Item = Result<(([u8; 48], [u8; 48], [u8; 48], [u8; 48]), [u8; 32]), PrecompileHalt>,
        >,
    ) -> Result<[u8; 192], PrecompileHalt> {
        #[cfg(all(target_os = "zkvm", target_vendor = "zisk"))]
        {
            let mut pairs_bytes = Vec::new();
            let mut num_pairs = 0usize;
            for pair in pairs {
                let (point, scalar) = pair?;
                pairs_bytes.extend_from_slice(&point.0);
                pairs_bytes.extend_from_slice(&point.1);
                pairs_bytes.extend_from_slice(&point.2);
                pairs_bytes.extend_from_slice(&point.3);
                pairs_bytes.extend_from_slice(&scalar);
                num_pairs += 1;
            }
            let mut result = zkvm_bls12_381_g2_point { data: [0u8; 192] };
            let ret = unsafe {
                zkvm_bls12_g2_msm(
                    pairs_bytes.as_ptr() as *const zkvm_bls12_381_g2_msm_pair,
                    num_pairs,
                    &mut result,
                )
            };
            if ret == zkvm_status_ZKVM_EOK {
                Ok(result.data)
            } else {
                Err(PrecompileHalt::other("bls12_381_g2_msm failed"))
            }
        }

        #[cfg(not(all(target_os = "zkvm", target_vendor = "zisk")))]
        {
            revm::precompile::DefaultCrypto.bls12_381_g2_msm(pairs)
        }
    }

    fn bls12_381_pairing_check(
        &self,
        pairs: &[(([u8; 48], [u8; 48]), ([u8; 48], [u8; 48], [u8; 48], [u8; 48]))],
    ) -> Result<bool, PrecompileHalt> {
        #[cfg(all(target_os = "zkvm", target_vendor = "zisk"))]
        {
            let mut pairs_bytes = Vec::new();
            for (g1, g2) in pairs {
                pairs_bytes.extend_from_slice(&g1.0);
                pairs_bytes.extend_from_slice(&g1.1);
                pairs_bytes.extend_from_slice(&g2.0);
                pairs_bytes.extend_from_slice(&g2.1);
                pairs_bytes.extend_from_slice(&g2.2);
                pairs_bytes.extend_from_slice(&g2.3);
            }
            let mut verified = false;
            let ret = unsafe {
                zkvm_bls12_pairing(
                    pairs_bytes.as_ptr() as *const zkvm_bls12_381_pairing_pair,
                    pairs.len(),
                    &mut verified,
                )
            };
            if ret == zkvm_status_ZKVM_EOK {
                Ok(verified)
            } else {
                Err(PrecompileHalt::other("bls12_381_pairing failed"))
            }
        }

        #[cfg(not(all(target_os = "zkvm", target_vendor = "zisk")))]
        {
            revm::precompile::DefaultCrypto.bls12_381_pairing_check(pairs)
        }
    }

    fn bls12_381_fp_to_g1(&self, fp: &[u8; 48]) -> Result<[u8; 96], PrecompileHalt> {
        #[cfg(all(target_os = "zkvm", target_vendor = "zisk"))]
        {
            let mut result = zkvm_bls12_381_g1_point { data: [0u8; 96] };
            let ret = unsafe {
                zkvm_bls12_map_fp_to_g1(fp.as_ptr() as *const zkvm_bls12_381_fp, &mut result)
            };
            if ret == zkvm_status_ZKVM_EOK {
                Ok(result.data)
            } else {
                Err(PrecompileHalt::other("bls12_381_fp_to_g1 failed"))
            }
        }

        #[cfg(not(all(target_os = "zkvm", target_vendor = "zisk")))]
        {
            revm::precompile::DefaultCrypto.bls12_381_fp_to_g1(fp)
        }
    }

    fn bls12_381_fp2_to_g2(&self, fp2: ([u8; 48], [u8; 48])) -> Result<[u8; 192], PrecompileHalt> {
        #[cfg(all(target_os = "zkvm", target_vendor = "zisk"))]
        {
            let mut fp2_bytes = [0u8; 96];
            fp2_bytes[..48].copy_from_slice(&fp2.0);
            fp2_bytes[48..].copy_from_slice(&fp2.1);

            let fp2_struct = zkvm_bls12_381_fp2 { data: fp2_bytes };
            let mut result = zkvm_bls12_381_g2_point { data: [0u8; 192] };
            let ret = unsafe { zkvm_bls12_map_fp2_to_g2(&fp2_struct, &mut result) };
            if ret == zkvm_status_ZKVM_EOK {
                Ok(result.data)
            } else {
                Err(PrecompileHalt::other("bls12_381_fp2_to_g2 failed"))
            }
        }

        #[cfg(not(all(target_os = "zkvm", target_vendor = "zisk")))]
        {
            revm::precompile::DefaultCrypto.bls12_381_fp2_to_g2(fp2)
        }
    }
}
