//! Disk cache for range guest stdin blobs.

use std::{
    fmt, fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use base_proof_zisk_client_utils::{BootInfoStruct, decode_boot_info, encode_boot_info};
use zisk_sdk::ZiskStdin;

/// Cached stdin and boot info for one range proof.
#[derive(Clone)]
pub struct CachedRangeStdin {
    /// `ZisK` stdin loaded from the cached framed stdin bytes.
    pub stdin: ZiskStdin,
    /// Boot info derived with the same witness that produced `stdin`, when a
    /// sidecar is available.
    pub boot_info: Option<BootInfoStruct>,
    /// Path to the cached framed stdin blob.
    pub stdin_path: PathBuf,
    /// Path to the boot info sidecar.
    pub boot_info_path: PathBuf,
}

impl fmt::Debug for CachedRangeStdin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CachedRangeStdin")
            .field("boot_info", &self.boot_info)
            .field("stdin_path", &self.stdin_path)
            .field("boot_info_path", &self.boot_info_path)
            .finish_non_exhaustive()
    }
}

/// Cache helpers for range guest stdin files.
#[derive(Debug)]
pub struct RangeWitnessCache;

impl RangeWitnessCache {
    /// Return the cache path for a range guest stdin blob.
    pub fn stdin_path(cache_dir: impl AsRef<Path>, start_block: u64, end_block: u64) -> PathBuf {
        cache_dir.as_ref().join(format!("{start_block}-{end_block}-stdin.bin"))
    }

    /// Return the cache path for a range guest boot info sidecar.
    pub fn boot_info_path(
        cache_dir: impl AsRef<Path>,
        start_block: u64,
        end_block: u64,
    ) -> PathBuf {
        cache_dir.as_ref().join(format!("{start_block}-{end_block}-boot-info.bin"))
    }

    /// Load a cached range stdin if the stdin file exists.
    pub fn load_stdin_from_cache(
        cache_dir: impl AsRef<Path>,
        start_block: u64,
        end_block: u64,
    ) -> Result<Option<CachedRangeStdin>> {
        let cache_dir = cache_dir.as_ref();
        let stdin_path = Self::stdin_path(cache_dir, start_block, end_block);
        if !stdin_path.exists() {
            return Ok(None);
        }

        let boot_info_path = Self::boot_info_path(cache_dir, start_block, end_block);
        let stdin = ZiskStdin::from_file(&stdin_path)
            .with_context(|| format!("load cached ZisK stdin {}", stdin_path.display()))?;
        let boot_info = if boot_info_path.exists() {
            let boot_info_bytes = fs::read(&boot_info_path)
                .with_context(|| format!("read cached boot info {}", boot_info_path.display()))?;
            Some(
                decode_boot_info(&boot_info_bytes).with_context(|| {
                    format!("decode cached boot info {}", boot_info_path.display())
                })?,
            )
        } else {
            None
        };

        Ok(Some(CachedRangeStdin { stdin, boot_info, stdin_path, boot_info_path }))
    }

    /// Save a range guest stdin and boot info sidecar to cache.
    pub fn save_stdin_to_cache(
        cache_dir: impl AsRef<Path>,
        start_block: u64,
        end_block: u64,
        stdin: &ZiskStdin,
        boot_info: &BootInfoStruct,
    ) -> Result<PathBuf> {
        let cache_dir = cache_dir.as_ref();
        fs::create_dir_all(cache_dir)
            .with_context(|| format!("create witness cache dir {}", cache_dir.display()))?;

        let stdin_path = Self::stdin_path(cache_dir, start_block, end_block);
        let stdin_temp_path = stdin_path.with_extension("bin.tmp");
        stdin
            .save(&stdin_temp_path)
            .with_context(|| format!("write cached ZisK stdin {}", stdin_temp_path.display()))?;
        fs::rename(&stdin_temp_path, &stdin_path).with_context(|| {
            format!(
                "install cached ZisK stdin {} -> {}",
                stdin_temp_path.display(),
                stdin_path.display()
            )
        })?;

        let boot_info_path = Self::boot_info_path(cache_dir, start_block, end_block);
        let boot_info_temp_path = boot_info_path.with_extension("bin.tmp");
        fs::write(&boot_info_temp_path, encode_boot_info(boot_info))
            .with_context(|| format!("write cached boot info {}", boot_info_temp_path.display()))?;
        fs::rename(&boot_info_temp_path, &boot_info_path).with_context(|| {
            format!(
                "install cached boot info {} -> {}",
                boot_info_temp_path.display(),
                boot_info_path.display()
            )
        })?;

        Ok(stdin_path)
    }
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use alloy_primitives::{B256, Bytes};
    use base_proof_zisk_client_utils::boot_info_commitment;

    use super::*;

    fn cache_dir() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before UNIX epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("base-zisk-witness-cache-{nanos}"))
    }

    fn boot_info() -> BootInfoStruct {
        BootInfoStruct {
            l1Head: B256::repeat_byte(0x11),
            l2PreRoot: B256::repeat_byte(0x22),
            l2PostRoot: B256::repeat_byte(0x33),
            l2PreBlockNumber: 10,
            l2BlockNumber: 11,
            rollupConfigHash: B256::repeat_byte(0x44),
            intermediateRoots: Bytes::from(vec![0x55; 32]),
        }
    }

    #[test]
    fn cache_roundtrip_preserves_stdin_and_boot_info() {
        let dir = cache_dir();
        let stdin = ZiskStdin::from_bytes(vec![1, 2, 3, 4]);
        let boot_info = boot_info();

        let saved_path = RangeWitnessCache::save_stdin_to_cache(&dir, 100, 101, &stdin, &boot_info)
            .expect("save stdin cache");
        let cached = RangeWitnessCache::load_stdin_from_cache(&dir, 100, 101)
            .expect("load stdin cache")
            .expect("cache entry exists");

        assert_eq!(saved_path, cached.stdin_path);
        assert_eq!(cached.stdin.read_bytes(), vec![1, 2, 3, 4]);
        let cached_boot_info = cached.boot_info.expect("boot info sidecar exists");
        assert_eq!(boot_info_commitment(&cached_boot_info), boot_info_commitment(&boot_info));

        fs::remove_dir_all(dir).expect("remove temp cache dir");
    }

    #[test]
    fn cache_loads_stdin_without_boot_info_sidecar() {
        let dir = cache_dir();
        fs::create_dir_all(&dir).expect("create temp cache dir");
        let stdin = ZiskStdin::from_bytes(vec![9, 8, 7, 6]);
        let stdin_path = RangeWitnessCache::stdin_path(&dir, 100, 101);
        stdin.save(&stdin_path).expect("save stdin cache");

        let cached = RangeWitnessCache::load_stdin_from_cache(&dir, 100, 101)
            .expect("load stdin cache")
            .expect("cache entry exists");

        assert_eq!(cached.stdin.read_bytes(), vec![9, 8, 7, 6]);
        assert!(cached.boot_info.is_none());

        fs::remove_dir_all(dir).expect("remove temp cache dir");
    }

    #[test]
    fn missing_cache_returns_none() {
        let dir = cache_dir();
        let cached =
            RangeWitnessCache::load_stdin_from_cache(&dir, 100, 101).expect("load missing cache");

        assert!(cached.is_none());
    }
}
