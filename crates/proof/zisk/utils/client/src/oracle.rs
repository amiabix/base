//! Oracle implementations for `ZisK` guest data access, including blob storage.

extern crate alloc;

use alloc::{boxed::Box, format, vec::Vec};

use alloy_consensus::Blob as AlloyBlob;
use alloy_eips::eip4844::kzg_to_versioned_hash;
use alloy_primitives::B256;
use ark_bls12_381::Fr;
use ark_ff::{BigInteger, FftField, Field, One, PrimeField, Zero, batch_inversion};
use async_trait::async_trait;
use base_consensus_derive::{BlobProvider, BlobProviderError};
use base_protocol::BlockInfo;
use revm_precompile::kzg_point_evaluation;
use sha2::{Digest, Sha256};

use crate::{BYTES_PER_BLOB, BlobData};

const BYTES_PER_FIELD_ELEMENT: usize = 32;
const FIELD_ELEMENTS_PER_BLOB: usize = 4096;
const FIELD_ELEMENTS_PER_EXT_BLOB: usize = 8192;
const FIAT_SHAMIR_PROTOCOL_DOMAIN: &[u8; 16] = b"FSBLOBVERIFY_V1_";

/// KZG commitment-indexed blob storage for the zkVM oracle.
#[derive(Clone, Debug, Default)]
pub struct BlobStore {
    versioned_blobs: Vec<(B256, AlloyBlob)>,
}

impl TryFrom<BlobData> for BlobStore {
    type Error = BlobProviderError;

    fn try_from(value: BlobData) -> Result<Self, Self::Error> {
        let BlobData { blobs, commitments, proofs } = value;

        if blobs.len() != commitments.len() {
            return Err(BlobProviderError::SidecarLengthMismatch(blobs.len(), commitments.len()));
        }
        if blobs.len() != proofs.len() {
            return Err(BlobProviderError::SidecarLengthMismatch(blobs.len(), proofs.len()));
        }

        let verifier = BlobKzgVerifier::new()?;
        for ((blob, commitment), proof) in blobs.iter().zip(&commitments).zip(&proofs) {
            verifier.verify_blob_kzg_proof(blob.0.as_slice(), &commitment.0, &proof.0)?;
        }

        let versioned_blobs = commitments
            .iter()
            .map(|commitment| kzg_to_versioned_hash(commitment.as_slice()))
            .zip(blobs.iter().map(|blob| AlloyBlob::from(blob.0)))
            .rev()
            .collect();

        Ok(Self { versioned_blobs })
    }
}

#[async_trait]
impl BlobProvider for BlobStore {
    type Error = BlobProviderError;

    async fn get_and_validate_blobs(
        &mut self,
        _: &BlockInfo,
        blob_hashes: &[B256],
    ) -> Result<Vec<Box<AlloyBlob>>, Self::Error> {
        if blob_hashes.len() > self.versioned_blobs.len() {
            return Err(BlobProviderError::NotEnoughBlobs(
                blob_hashes.len(),
                self.versioned_blobs.len(),
            ));
        }

        let mut blobs = Vec::with_capacity(blob_hashes.len());
        for expected_hash in blob_hashes {
            let Some((actual_hash, blob)) = self.versioned_blobs.pop() else {
                return Err(BlobProviderError::NotEnoughBlobs(blob_hashes.len(), blobs.len()));
            };

            if *expected_hash != actual_hash {
                return Err(BlobProviderError::Backend(format!(
                    "blob versioned hash mismatch: expected {expected_hash:?}, got {actual_hash:?}"
                )));
            }

            blobs.push(Box::new(blob));
        }

        Ok(blobs)
    }
}

/// EIP-4844 blob KZG proof verifier for `ZisK` guest-side sidecar validation.
#[derive(Clone, Debug)]
pub struct BlobKzgVerifier {
    roots: Vec<Fr>,
}

impl BlobKzgVerifier {
    /// Creates a verifier with the bit-reversed roots needed for blob interpolation.
    pub fn new() -> Result<Self, BlobProviderError> {
        let root = Fr::get_root_of_unity(FIELD_ELEMENTS_PER_EXT_BLOB as u64).ok_or_else(|| {
            BlobProviderError::Backend("failed to compute blob roots of unity".into())
        })?;
        let mut roots = Vec::with_capacity(FIELD_ELEMENTS_PER_EXT_BLOB);
        let mut current = Fr::one();
        for _ in 0..FIELD_ELEMENTS_PER_EXT_BLOB {
            roots.push(current);
            current *= root;
        }

        let mut bit_reversed_roots = Vec::with_capacity(FIELD_ELEMENTS_PER_BLOB);
        for index in 0..FIELD_ELEMENTS_PER_BLOB {
            bit_reversed_roots.push(roots[Self::bit_reverse(index, 13)]);
        }

        Ok(Self { roots: bit_reversed_roots })
    }

    /// Verifies a blob proof against its commitment.
    pub fn verify_blob_kzg_proof(
        &self,
        blob: &[u8],
        commitment: &[u8; 48],
        proof: &[u8; 48],
    ) -> Result<(), BlobProviderError> {
        if blob.len() != BYTES_PER_BLOB {
            return Err(BlobProviderError::Backend(format!(
                "invalid blob length: expected {BYTES_PER_BLOB}, got {}",
                blob.len()
            )));
        }

        let polynomial = Self::blob_to_polynomial(blob)?;
        let challenge = Self::compute_challenge(blob, commitment);
        let evaluation = self.evaluate_polynomial_in_evaluation_form(&polynomial, challenge);
        let challenge_bytes = Self::fr_to_be_bytes(challenge);
        let evaluation_bytes = Self::fr_to_be_bytes(evaluation);

        if !kzg_point_evaluation::verify_kzg_proof(
            commitment,
            &challenge_bytes,
            &evaluation_bytes,
            proof,
        ) {
            return Err(BlobProviderError::Backend("KZG blob proof verification failed".into()));
        }

        Ok(())
    }

    const fn bit_reverse(value: usize, bits: u32) -> usize {
        value.reverse_bits() >> (usize::BITS - bits)
    }

    fn blob_to_polynomial(blob: &[u8]) -> Result<Vec<Fr>, BlobProviderError> {
        let mut polynomial = Vec::with_capacity(FIELD_ELEMENTS_PER_BLOB);
        for chunk in blob.chunks_exact(BYTES_PER_FIELD_ELEMENT) {
            let mut field_bytes = [0u8; BYTES_PER_FIELD_ELEMENT];
            field_bytes.copy_from_slice(chunk);
            polynomial.push(Self::read_scalar_canonical(&field_bytes)?);
        }
        Ok(polynomial)
    }

    fn read_scalar_canonical(
        bytes: &[u8; BYTES_PER_FIELD_ELEMENT],
    ) -> Result<Fr, BlobProviderError> {
        let value = Fr::from_be_bytes_mod_order(bytes);
        if Self::fr_to_be_bytes(value) != *bytes {
            return Err(BlobProviderError::Backend(
                "invalid non-canonical blob field element".into(),
            ));
        }
        Ok(value)
    }

    fn compute_challenge(blob: &[u8], commitment: &[u8; 48]) -> Fr {
        let mut hasher = Sha256::new();
        hasher.update(FIAT_SHAMIR_PROTOCOL_DOMAIN);
        hasher.update(0u64.to_be_bytes());
        hasher.update((FIELD_ELEMENTS_PER_BLOB as u64).to_be_bytes());
        hasher.update(blob);
        hasher.update(commitment);
        let digest = hasher.finalize();
        Fr::from_be_bytes_mod_order(&digest)
    }

    fn evaluate_polynomial_in_evaluation_form(&self, polynomial: &[Fr], point: Fr) -> Fr {
        for (index, root) in self.roots.iter().enumerate() {
            if point == *root {
                return polynomial[index];
            }
        }

        let mut inverses = self.roots.iter().map(|root| point - root).collect::<Vec<_>>();
        batch_inversion(&mut inverses);

        let mut output = Fr::zero();
        for ((inverse, root), value) in inverses.iter().zip(&self.roots).zip(polynomial) {
            output += inverse * root * value;
        }

        output /= Fr::from(FIELD_ELEMENTS_PER_BLOB as u64);
        output *= point.pow([FIELD_ELEMENTS_PER_BLOB as u64]) - Fr::one();
        output
    }

    fn fr_to_be_bytes(value: Fr) -> [u8; BYTES_PER_FIELD_ELEMENT] {
        let bytes = value.into_bigint().to_bytes_be();
        let mut output = [0u8; BYTES_PER_FIELD_ELEMENT];
        let start = output.len().saturating_sub(bytes.len());
        output[start..].copy_from_slice(&bytes);
        output
    }
}

#[cfg(test)]
mod tests {
    use c_kzg::{Blob as CkzgBlob, ethereum_kzg_settings};

    use super::*;

    #[test]
    fn verifies_blob_proof_generated_by_ckzg() {
        let mut blob_bytes = [0u8; BYTES_PER_BLOB];
        blob_bytes[31] = 1;
        blob_bytes[63] = 2;

        let blob = CkzgBlob::from_bytes(&blob_bytes).expect("valid test blob");
        let settings = ethereum_kzg_settings(0);
        let commitment = settings.blob_to_kzg_commitment(&blob).expect("compute commitment");
        let proof = settings
            .compute_blob_kzg_proof(&blob, &commitment.to_bytes())
            .expect("compute blob proof");
        let verifier = BlobKzgVerifier::new().expect("compute roots of unity");

        verifier
            .verify_blob_kzg_proof(
                &blob_bytes,
                &commitment.to_bytes().into_inner(),
                &proof.to_bytes().into_inner(),
            )
            .expect("valid blob proof");

        blob_bytes[31] = 3;
        let result = verifier.verify_blob_kzg_proof(
            &blob_bytes,
            &commitment.to_bytes().into_inner(),
            &proof.to_bytes().into_inner(),
        );
        assert!(result.is_err(), "tampered blob must fail proof verification");
    }
}
