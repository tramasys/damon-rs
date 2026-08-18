//! Receipt-verified persistent DAMON lifecycle operations.

use std::path::{Component, Path, PathBuf};
use std::sync::OnceLock;

use super::{
    ConfigurationSnapshot, Damon, DamonConfig, Error, ManagedHierarchy, ObservedConfiguration, Pid,
    Result, SessionLock, StagedOwnership, WritableConfigurationValue, with_rollback,
};

const RECEIPT_MAGIC: &[u8; 8] = b"DAMONR01";
const RECEIPT_VERSION: u32 = 1;

/// A running kdamond identity recorded in a persistent receipt.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PersistentKdamondIdentity {
    index: usize,
    pid: Pid,
}

impl PersistentKdamondIdentity {
    /// Returns the kdamond hierarchy index.
    #[must_use]
    pub const fn index(self) -> usize {
        self.index
    }

    /// Returns the kernel-thread ID observed immediately after start.
    #[must_use]
    pub const fn pid(self) -> Pid {
        self.pid
    }
}

/// Verification data for a persistent DAMON hierarchy.
///
/// A receipt is evidence of an observed configuration and set of kernel-thread
/// IDs. It is not an ownership token. A controller that ignores the advisory
/// lock can replace a hierarchy between persistent operations.
#[must_use = "persistent receipts are required for later verified lifecycle operations"]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistentReceipt {
    admin_path: PathBuf,
    lock_path: PathBuf,
    boot_id: Box<str>,
    writable_values: Box<[WritableConfigurationValue]>,
    volatile_paths: Box<[PathBuf]>,
    kdamond_count: usize,
    identities: Box<[PersistentKdamondIdentity]>,
}

impl PersistentReceipt {
    fn capture(damon: &Damon, managed: &ManagedHierarchy) -> Result<Self> {
        let parts = managed.persistent_parts()?;
        let volatile_paths = parts
            .volatile_paths
            .iter()
            .map(|path| {
                path.strip_prefix(damon.admin.path())
                    .map(Path::to_path_buf)
                    .map_err(|_| Error::OwnershipLost {
                        reason: "a volatile configuration path escaped the DAMON admin root",
                    })
            })
            .collect::<Result<Vec<_>>>()?
            .into_boxed_slice();
        let identities = parts
            .identities
            .iter()
            .map(|&(index, pid)| PersistentKdamondIdentity { index, pid })
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Ok(Self {
            admin_path: damon.admin.path().to_path_buf(),
            lock_path: damon.lock_path.clone(),
            boot_id: current_boot_id()?.into(),
            writable_values: parts.configuration.writable_values(),
            volatile_paths,
            kdamond_count: parts.kdamond_count,
            identities,
        })
    }

    /// Returns the DAMON admin path to which this receipt is bound.
    #[must_use]
    pub fn admin_path(&self) -> &Path {
        &self.admin_path
    }

    /// Returns the cooperative lock path to which this receipt is bound.
    #[must_use]
    pub fn lock_path(&self) -> &Path {
        &self.lock_path
    }

    /// Returns the Linux boot identifier to which this receipt is bound.
    #[must_use]
    pub const fn boot_id(&self) -> &str {
        &self.boot_id
    }

    /// Returns the running kdamond identities recorded by the receipt.
    #[must_use]
    pub const fn identities(&self) -> &[PersistentKdamondIdentity] {
        &self.identities
    }

    /// Returns the total number of configured kdamonds, including stopped ones.
    #[must_use]
    pub const fn kdamond_count(&self) -> usize {
        self.kdamond_count
    }

    /// Returns all recorded writable configuration values.
    #[must_use]
    pub const fn writable_values(&self) -> &[WritableConfigurationValue] {
        &self.writable_values
    }

    /// Serializes this receipt into a stable versioned binary representation.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut output = Vec::new();
        output.extend_from_slice(RECEIPT_MAGIC);
        output.extend_from_slice(&RECEIPT_VERSION.to_le_bytes());
        encode_path(&mut output, &self.admin_path)?;
        encode_path(&mut output, &self.lock_path)?;
        encode_bytes(&mut output, self.boot_id.as_bytes())?;
        encode_len(&mut output, self.writable_values.len())?;
        for value in &self.writable_values {
            encode_path(&mut output, value.path())?;
            encode_bytes(&mut output, value.value().as_bytes())?;
        }
        encode_len(&mut output, self.volatile_paths.len())?;
        for path in &self.volatile_paths {
            encode_path(&mut output, path)?;
        }
        encode_len(&mut output, self.kdamond_count)?;
        encode_len(&mut output, self.identities.len())?;
        for identity in &self.identities {
            output.extend_from_slice(
                &u64::try_from(identity.index)
                    .map_err(|_| Error::InvalidReceipt {
                        reason: "a kdamond index cannot be serialized",
                    })?
                    .to_le_bytes(),
            );
            output.extend_from_slice(&u32::from(identity.pid).to_le_bytes());
        }
        Ok(output)
    }

    /// Parses a receipt serialized by [`Self::to_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut decoder = Decoder::new(bytes);
        if decoder.take(RECEIPT_MAGIC.len())? != RECEIPT_MAGIC {
            return Err(Error::InvalidReceipt {
                reason: "has an invalid format marker",
            });
        }
        if decoder.read_u32()? != RECEIPT_VERSION {
            return Err(Error::InvalidReceipt {
                reason: "uses an unsupported format version",
            });
        }
        let admin_path = decoder.read_path()?;
        let lock_path = decoder.read_path()?;
        let boot_id =
            Box::<str>::from(std::str::from_utf8(decoder.read_bytes()?).map_err(|_| {
                Error::InvalidReceipt {
                    reason: "contains a non-UTF-8 boot identifier",
                }
            })?);
        if !admin_path.is_absolute()
            || !lock_path.is_absolute()
            || path_contains_nul(&admin_path)
            || path_contains_nul(&lock_path)
        {
            return Err(Error::InvalidReceipt {
                reason: "admin and lock paths must be absolute and contain no NUL bytes",
            });
        }
        validate_boot_id(&boot_id)?;

        let value_count = decoder.read_count()?;
        let mut writable_values = Vec::with_capacity(value_count.min(4_096));
        for _ in 0..value_count {
            let path = decoder.read_path()?;
            validate_relative_path(&path)?;
            let value = std::str::from_utf8(decoder.read_bytes()?)
                .map_err(|_| Error::InvalidReceipt {
                    reason: "contains a non-UTF-8 configuration value",
                })?
                .into();
            writable_values.push(WritableConfigurationValue::new(path, value));
        }

        let volatile_count = decoder.read_count()?;
        let mut volatile_paths = Vec::with_capacity(volatile_count.min(64));
        for _ in 0..volatile_count {
            let path = decoder.read_path()?;
            validate_relative_path(&path)?;
            volatile_paths.push(path);
        }

        let kdamond_count = decoder.read_count()?;
        if kdamond_count == 0 {
            return Err(Error::InvalidReceipt {
                reason: "contains no configured kdamonds",
            });
        }
        let identity_count = decoder.read_count()?;
        if identity_count > kdamond_count {
            return Err(Error::InvalidReceipt {
                reason: "contains more running identities than configured kdamonds",
            });
        }
        let mut identities = Vec::with_capacity(identity_count.min(1_024));
        let mut previous_index = None;
        for _ in 0..identity_count {
            let index =
                usize::try_from(decoder.read_u64()?).map_err(|_| Error::InvalidReceipt {
                    reason: "contains an out-of-range kdamond index",
                })?;
            if index >= kdamond_count {
                return Err(Error::InvalidReceipt {
                    reason: "contains a running identity outside the hierarchy",
                });
            }
            if previous_index.is_some_and(|previous| previous >= index) {
                return Err(Error::InvalidReceipt {
                    reason: "running kdamond identities are not distinct and ordered",
                });
            }
            let pid = Pid::new(decoder.read_u32()?).map_err(|_| Error::InvalidReceipt {
                reason: "contains an invalid kdamond kernel-thread ID",
            })?;
            identities.push(PersistentKdamondIdentity { index, pid });
            previous_index = Some(index);
        }
        if !decoder.is_empty() {
            return Err(Error::InvalidReceipt {
                reason: "contains trailing data",
            });
        }
        Ok(Self {
            admin_path,
            lock_path,
            boot_id,
            writable_values: writable_values.into_boxed_slice(),
            volatile_paths: volatile_paths.into_boxed_slice(),
            kdamond_count,
            identities: identities.into_boxed_slice(),
        })
    }

    fn verify_binding(&self, damon: &Damon) -> Result<()> {
        if self.admin_path != damon.admin.path() {
            return Err(Error::ReceiptMismatch {
                reason: "DAMON admin path differs",
            });
        }
        if self.lock_path != damon.lock_path {
            return Err(Error::ReceiptMismatch {
                reason: "advisory lock path differs",
            });
        }
        if self.boot_id.as_ref() != current_boot_id()? {
            return Err(Error::ReceiptMismatch {
                reason: "Linux boot identifier differs",
            });
        }
        Ok(())
    }

    fn open_managed(&self, damon: &Damon) -> Result<ManagedHierarchy> {
        self.verify_binding(damon)?;
        let session_lock = SessionLock::acquire(&damon.lock_path)?;
        let configuration =
            ConfigurationSnapshot::from_writable_values(damon.admin.path(), &self.writable_values)?;
        let volatile_paths = self
            .volatile_paths
            .iter()
            .map(|path| damon.admin.path().join(path))
            .collect::<Vec<_>>();
        let staged = StagedOwnership::from_parts(configuration, volatile_paths, self.kdamond_count);
        let identities = self
            .identities
            .iter()
            .map(|identity| (identity.index, identity.pid))
            .collect::<Vec<_>>();
        ManagedHierarchy::attach_persistent(damon.admin.clone(), staged, &identities, session_lock)
    }
}

/// A persistent hierarchy handle that verifies a receipt for each operation.
///
/// This handle does not retain the advisory lock between calls. Each mutating
/// operation reacquires it and rejects configuration or PID replacement before
/// writing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttachedHierarchy {
    damon: Damon,
    receipt: PersistentReceipt,
}

impl AttachedHierarchy {
    /// Returns the receipt currently verified by this handle.
    pub const fn receipt(&self) -> &PersistentReceipt {
        &self.receipt
    }

    /// Consumes the handle and returns its current receipt.
    pub fn into_receipt(self) -> PersistentReceipt {
        self.receipt
    }

    /// Reads the verified known configuration.
    pub fn configuration(&self) -> Result<DamonConfig> {
        let mut managed = self.receipt.open_managed(&self.damon)?;
        let result = managed.configuration();
        managed.disarm_cleanup();
        result
    }

    /// Reads the verified known hierarchy and every writable configuration value.
    pub fn observed_configuration(&self) -> Result<ObservedConfiguration> {
        let mut managed = self.receipt.open_managed(&self.damon)?;
        let result = managed.observed_configuration();
        managed.disarm_cleanup();
        result
    }

    /// Transactionally updates every running kdamond and replaces the receipt.
    pub fn update(&mut self, config: &DamonConfig) -> Result<()> {
        let indices = self
            .receipt
            .identities
            .iter()
            .map(|identity| identity.index)
            .collect::<Vec<_>>();
        self.update_selected(config, &indices)
    }

    /// Transactionally updates selected running kdamonds and replaces the receipt.
    pub fn update_selected(
        &mut self,
        config: &DamonConfig,
        kdamond_indices: &[usize],
    ) -> Result<()> {
        let mut managed = self.receipt.open_managed(&self.damon)?;
        let operation = managed.update_configuration(config, kdamond_indices);
        let receipt = PersistentReceipt::capture(&self.damon, &managed);
        managed.disarm_cleanup();
        match (operation, receipt) {
            (Ok(()), Ok(receipt)) => {
                self.receipt = receipt;
                Ok(())
            }
            (Err(operation), Ok(receipt)) => {
                self.receipt = receipt;
                Err(operation)
            }
            (operation, Err(verification)) => Err(Error::PersistentStateUncertain {
                operation: operation.err().map(Box::new),
                verification: Box::new(verification),
            }),
        }
    }

    /// Stops every kdamond whose recorded configuration and PID still match.
    ///
    /// The staged hierarchy is retained because a persistent receipt has no
    /// preceding hierarchy to restore.
    pub fn stop(&mut self) -> Result<()> {
        let mut managed = self.receipt.open_managed(&self.damon)?;
        let operation = managed.stop_all();
        let receipt = PersistentReceipt::capture(&self.damon, &managed);
        managed.disarm_cleanup();
        match (operation, receipt) {
            (Ok(()), Ok(receipt)) => {
                self.receipt = receipt;
                Ok(())
            }
            (Err(operation), Ok(receipt)) => {
                self.receipt = receipt;
                Err(operation)
            }
            (operation, Err(verification)) => Err(Error::PersistentStateUncertain {
                operation: operation.err().map(Box::new),
                verification: Box::new(verification),
            }),
        }
    }
}

impl Damon {
    /// Stages and starts a hierarchy that remains running after this call.
    ///
    /// The returned receipt must be persisted by the caller. It supports later
    /// verified attach, update, and stop operations, but cannot prevent an
    /// external controller from replacing the hierarchy between operations.
    pub fn start_persistent(&self, config: &DamonConfig) -> Result<PersistentReceipt> {
        let mut managed = self.managed_hierarchy(config)?;
        managed.start_all()?;
        match PersistentReceipt::capture(self, &managed) {
            Ok(receipt) => {
                managed.disarm_cleanup();
                Ok(receipt)
            }
            Err(operation) => Err(with_rollback(operation, managed.close_inner())),
        }
    }

    /// Attaches a receipt-verified persistent handle to this DAMON instance.
    pub fn attach(&self, receipt: &PersistentReceipt) -> Result<AttachedHierarchy> {
        let mut managed = receipt.open_managed(self)?;
        managed.disarm_cleanup();
        Ok(AttachedHierarchy {
            damon: self.clone(),
            receipt: receipt.clone(),
        })
    }
}

fn validate_relative_path(path: &Path) -> Result<()> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path_contains_nul(path)
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(Error::InvalidReceipt {
            reason: "contains a non-relative configuration path",
        });
    }
    Ok(())
}

fn current_boot_id() -> Result<&'static str> {
    #[cfg(target_os = "linux")]
    {
        const BOOT_ID_PATH: &str = "/proc/sys/kernel/random/boot_id";
        static BOOT_ID: OnceLock<Box<str>> = OnceLock::new();

        if let Some(value) = BOOT_ID.get() {
            return Ok(value);
        }
        let value = std::fs::read_to_string(BOOT_ID_PATH).map_err(|source| Error::Io {
            operation: "read Linux boot identifier",
            path: PathBuf::from(BOOT_ID_PATH),
            source,
        })?;
        let value = value.trim();
        validate_boot_id(value)?;
        let _ = BOOT_ID.set(value.into());
        Ok(BOOT_ID
            .get()
            .expect("the validated Linux boot identifier was cached"))
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(Error::UnsupportedPlatform)
    }
}

fn validate_boot_id(value: &str) -> Result<()> {
    let valid = value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        });
    if !valid {
        return Err(Error::InvalidReceipt {
            reason: "contains an invalid Linux boot identifier",
        });
    }
    Ok(())
}

fn path_contains_nul(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;

        path.as_os_str().as_bytes().contains(&0)
    }
    #[cfg(not(unix))]
    {
        path.to_string_lossy().contains('\0')
    }
}

fn encode_len(output: &mut Vec<u8>, len: usize) -> Result<()> {
    let len = u64::try_from(len).map_err(|_| Error::InvalidReceipt {
        reason: "contains a value too large to serialize",
    })?;
    output.extend_from_slice(&len.to_le_bytes());
    Ok(())
}

fn encode_bytes(output: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    encode_len(output, bytes.len())?;
    output.extend_from_slice(bytes);
    Ok(())
}

fn encode_path(output: &mut Vec<u8>, path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;

        encode_bytes(output, path.as_os_str().as_bytes())
    }
    #[cfg(not(unix))]
    {
        let value = path.to_str().ok_or(Error::InvalidReceipt {
            reason: "contains a platform path that is not valid UTF-8",
        })?;
        encode_bytes(output, value.as_bytes())
    }
}

struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self.offset.checked_add(len).ok_or(Error::InvalidReceipt {
            reason: "contains an overflowing length",
        })?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(Error::InvalidReceipt {
                reason: "is truncated",
            })?;
        self.offset = end;
        Ok(value)
    }

    fn read_u32(&mut self) -> Result<u32> {
        let bytes = self.take(size_of::<u32>())?;
        Ok(u32::from_le_bytes(
            bytes.try_into().expect("the decoder returned four bytes"),
        ))
    }

    fn read_u64(&mut self) -> Result<u64> {
        let bytes = self.take(size_of::<u64>())?;
        Ok(u64::from_le_bytes(
            bytes.try_into().expect("the decoder returned eight bytes"),
        ))
    }

    fn read_count(&mut self) -> Result<usize> {
        let count = usize::try_from(self.read_u64()?).map_err(|_| Error::InvalidReceipt {
            reason: "contains an out-of-range element count",
        })?;
        if count > self.bytes.len().saturating_sub(self.offset) {
            return Err(Error::InvalidReceipt {
                reason: "contains an impossible element count",
            });
        }
        Ok(count)
    }

    fn read_bytes(&mut self) -> Result<&'a [u8]> {
        let len = self.read_count()?;
        self.take(len)
    }

    fn read_path(&mut self) -> Result<PathBuf> {
        let bytes = self.read_bytes()?;
        #[cfg(unix)]
        {
            use std::ffi::OsString;
            use std::os::unix::ffi::OsStringExt;

            Ok(PathBuf::from(OsString::from_vec(bytes.to_vec())))
        }
        #[cfg(not(unix))]
        {
            Ok(PathBuf::from(std::str::from_utf8(bytes).map_err(|_| {
                Error::InvalidReceipt {
                    reason: "contains a platform path that is not valid UTF-8",
                }
            })?))
        }
    }

    fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }
}
