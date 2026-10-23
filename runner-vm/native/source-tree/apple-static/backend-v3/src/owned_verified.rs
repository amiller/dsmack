// VENDORED VERBATIM from morning/source3 libkrun
use crate::arch;

// Copyright 2024, Red Hat Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;

use sha2::{Digest, Sha256};

#[cfg_attr(feature = "ffi", ffier::export)]
#[repr(u32)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[allow(unused)]
pub enum KernelFormat {
    // ELF image, need to locale sections be loaded.
    Elf = 0,
    // Raw image, ready to be loaded into the VM.
    #[default]
    Raw = 1,
    // Raw image compressed with GZIP, embedded into a PE file.
    PeGz = 2,
    // ELF image compressed with BZIP2, embedded into an Image file.
    ImageBz2 = 3,
    // ELF image compressed with GZIP, embedded into an Image file.
    ImageGz = 4,
    // ELF image compressed with ZSTD, embedded into an Image file.
    ImageZstd = 5,
}

pub const VERIFIED_KERNEL_MAX_BYTES: usize = 64 << 20;
pub const VERIFIED_INITRD_MAX_BYTES: usize = 256 << 20;
pub const VERIFIED_CMDLINE_MAX_BYTES: usize = 4096;

#[derive(Clone, Debug)]
pub enum ExternalKernelSource {
    Path {
        kernel: PathBuf,
        initramfs: Option<PathBuf>,
    },
    Verified(VerifiedBootImages),
}

/// Data structure holding the attributes read from the `libkrunfw` kernel config.
#[derive(Clone, Debug)]
#[allow(unused)]
pub struct ExternalKernel {
    pub source: ExternalKernelSource,
    pub format: KernelFormat,
    pub initramfs_size: u64,
    pub cmdline: Option<String>,
}

impl ExternalKernel {
    pub fn verified(&self) -> Option<&VerifiedBootImages> {
        match &self.source {
            ExternalKernelSource::Verified(images) => Some(images),
            ExternalKernelSource::Path { .. } => None,
        }
    }
}

/// Lowercase hex SHA-256 pins for the verified boot route. They are policy inputs: the
/// caller must take them from constants compiled into its signed binary or from an
/// independently approved manifest, never from the bytes being checked.
#[derive(Clone, Copy, Debug)]
pub struct VerifiedBootPins<'a> {
    pub kernel_sha256: &'a str,
    pub initrd_sha256: Option<&'a str>,
    pub cmdline_sha256: &'a str,
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum VerifiedBootError {
    #[error("kernel is empty")]
    KernelEmpty,
    #[error("kernel is {0} bytes, limit {VERIFIED_KERNEL_MAX_BYTES}")]
    KernelTooLarge(usize),
    #[error("initrd is empty")]
    InitrdEmpty,
    #[error("initrd is {0} bytes, limit {VERIFIED_INITRD_MAX_BYTES}")]
    InitrdTooLarge(usize),
    #[error("initrd presence does not match initrd pin presence")]
    InitrdPinPresence,
    #[error("cmdline contains a byte outside printable ASCII")]
    CmdlineInvalid,
    #[error("cmdline is {0} bytes, limit {1}")]
    CmdlineTooLong(usize, usize),
    #[error("{0} pin is not 64 lowercase hex characters")]
    PinSyntax(&'static str),
    #[error("{0} SHA-256 does not match its pin")]
    HashMismatch(&'static str),
}

/// Kernel, optional initrd and cmdline copied into libkrun-owned immutable storage. The
/// only constructor checks the owned copies against the pins.
#[derive(Clone)]
pub struct VerifiedBootImages {
    kernel: Arc<[u8]>,
    initrd: Option<Arc<[u8]>>,
    cmdline: String,
}

fn check_pin_syntax(pin: &str, what: &'static str) -> Result<(), VerifiedBootError> {
    if pin.len() == 64 && pin.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')) {
        Ok(())
    } else {
        Err(VerifiedBootError::PinSyntax(what))
    }
}

fn check_hash(data: &[u8], pin: &str, what: &'static str) -> Result<(), VerifiedBootError> {
    if format!("{:x}", Sha256::digest(data)) == pin {
        Ok(())
    } else {
        Err(VerifiedBootError::HashMismatch(what))
    }
}

impl VerifiedBootImages {
    pub fn new(
        kernel: &[u8],
        initrd: Option<&[u8]>,
        cmdline: &str,
        pins: &VerifiedBootPins,
    ) -> Result<Self, VerifiedBootError> {
        use VerifiedBootError::*;

        if kernel.is_empty() {
            return Err(KernelEmpty);
        }
        if kernel.len() > VERIFIED_KERNEL_MAX_BYTES {
            return Err(KernelTooLarge(kernel.len()));
        }
        if initrd.is_some() != pins.initrd_sha256.is_some() {
            return Err(InitrdPinPresence);
        }
        if let Some(initrd) = initrd {
            if initrd.is_empty() {
                return Err(InitrdEmpty);
            }
            if initrd.len() > VERIFIED_INITRD_MAX_BYTES {
                return Err(InitrdTooLarge(initrd.len()));
            }
        }
        if !cmdline.bytes().all(|c| matches!(c, b' '..=b'~')) {
            return Err(CmdlineInvalid);
        }
        // arch::CMDLINE_MAX_SIZE includes the NUL terminator.
        let cmdline_max = VERIFIED_CMDLINE_MAX_BYTES.min(arch::CMDLINE_MAX_SIZE - 1);
        if cmdline.len() > cmdline_max {
            return Err(CmdlineTooLong(cmdline.len(), cmdline_max));
        }
        check_pin_syntax(pins.kernel_sha256, "kernel")?;
        if let Some(pin) = pins.initrd_sha256 {
            check_pin_syntax(pin, "initrd")?;
        }
        check_pin_syntax(pins.cmdline_sha256, "cmdline")?;

        let images = VerifiedBootImages {
            kernel: Arc::from(kernel),
            initrd: initrd.map(Arc::from),
            cmdline: cmdline.to_string(),
        };
        check_hash(&images.kernel, pins.kernel_sha256, "kernel")?;
        if let (Some(data), Some(pin)) = (&images.initrd, pins.initrd_sha256) {
            check_hash(data, pin, "initrd")?;
        }
        check_hash(images.cmdline.as_bytes(), pins.cmdline_sha256, "cmdline")?;
        Ok(images)
    }

        pub fn kernel(&self) -> &[u8] {
        &self.kernel
    }

    pub fn initrd(&self) -> Option<&[u8]> {
        self.initrd.as_deref()
    }

    pub fn cmdline(&self) -> &str {
        &self.cmdline
    }
}

impl fmt::Debug for VerifiedBootImages {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifiedBootImages")
            .field("kernel_len", &self.kernel.len())
            .field("initrd_len", &self.initrd.as_ref().map(|i| i.len()))
            .field("cmdline", &self.cmdline)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ABC_SHA256: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    fn sha(data: &[u8]) -> String {
        format!("{:x}", Sha256::digest(data))
    }

    fn images(
        kernel: &[u8],
        initrd: Option<&[u8]>,
        cmdline: &str,
    ) -> Result<VerifiedBootImages, VerifiedBootError> {
        let (k, i, c) = (sha(kernel), initrd.map(sha), sha(cmdline.as_bytes()));
        let pins = VerifiedBootPins {
            kernel_sha256: &k,
            initrd_sha256: i.as_deref(),
            cmdline_sha256: &c,
        };
        VerifiedBootImages::new(kernel, initrd, cmdline, &pins)
    }

    #[test]
    fn verified_literal_pin_accepts_owned_copy() {
        let cmdline_pin = sha(b"console=hvc0");
        let pins = VerifiedBootPins {
            kernel_sha256: ABC_SHA256,
            initrd_sha256: Some(ABC_SHA256),
            cmdline_sha256: &cmdline_pin,
        };
        let caller = b"abc".to_vec();
        let v = VerifiedBootImages::new(&caller, Some(&caller), "console=hvc0", &pins).unwrap();
        assert_eq!(v.kernel(), b"abc");
        assert_eq!(v.initrd(), Some(&b"abc"[..]));
        assert_ne!(v.kernel().as_ptr(), caller.as_ptr());
    }

    #[test]
    fn verified_wrong_pins_refuse() {
        let other = sha(b"other");
        let (k, i, c) = (sha(b"kernel"), sha(b"initrd"), sha(b"cmd"));
        let cases = [
            (other.as_str(), i.as_str(), c.as_str(), "kernel"),
            (k.as_str(), other.as_str(), c.as_str(), "initrd"),
            (k.as_str(), i.as_str(), other.as_str(), "cmdline"),
        ];
        for (kp, ip, cp, what) in cases {
            let pins = VerifiedBootPins {
                kernel_sha256: kp,
                initrd_sha256: Some(ip),
                cmdline_sha256: cp,
            };
            assert_eq!(
                VerifiedBootImages::new(b"kernel", Some(b"initrd"), "cmd", &pins).unwrap_err(),
                VerifiedBootError::HashMismatch(what)
            );
        }
    }

    #[test]
    fn verified_mutation_before_copy_refuses() {
        let mut kernel = b"approved kernel".to_vec();
        let pin = sha(&kernel);
        let cmd = sha(b"");
        kernel[0] ^= 1;
        let pins = VerifiedBootPins {
            kernel_sha256: &pin,
            initrd_sha256: None,
            cmdline_sha256: &cmd,
        };
        assert_eq!(
            VerifiedBootImages::new(&kernel, None, "", &pins).unwrap_err(),
            VerifiedBootError::HashMismatch("kernel")
        );
    }

    #[test]
    fn verified_mutation_or_drop_after_copy_does_not_change_owned_bytes() {
        let mut kernel = b"approved kernel".to_vec();
        let mut initrd = b"approved initrd".to_vec();
        let (kp, ip) = (sha(&kernel), sha(&initrd));
        let v = images(&kernel, Some(&initrd), "ro").unwrap();
        kernel.fill(0);
        initrd.fill(0);
        drop(kernel);
        drop(initrd);
        assert_eq!(sha(v.kernel()), kp);
        assert_eq!(sha(v.initrd().unwrap()), ip);
        let cloned = v.clone();
        drop(v);
        assert_eq!(sha(cloned.kernel()), kp);
    }

    #[test]
    fn verified_initrd_presence_must_match_pin() {
        let (k, c) = (sha(b"k"), sha(b""));
        let mut pins = VerifiedBootPins {
            kernel_sha256: &k,
            initrd_sha256: None,
            cmdline_sha256: &c,
        };
        assert_eq!(
            VerifiedBootImages::new(b"k", Some(b"i"), "", &pins).unwrap_err(),
            VerifiedBootError::InitrdPinPresence
        );
        pins.initrd_sha256 = Some(ABC_SHA256);
        assert_eq!(
            VerifiedBootImages::new(b"k", None, "", &pins).unwrap_err(),
            VerifiedBootError::InitrdPinPresence
        );
        let empty = sha(b"");
        pins.initrd_sha256 = Some(&empty);
        assert_eq!(
            VerifiedBootImages::new(b"k", Some(b""), "", &pins).unwrap_err(),
            VerifiedBootError::InitrdEmpty
        );
    }

    #[test]
    fn verified_sizes_fail_closed() {
        assert_eq!(
            images(b"", None, "").unwrap_err(),
            VerifiedBootError::KernelEmpty
        );
        let big = vec![0u8; VERIFIED_KERNEL_MAX_BYTES + 1];
        assert_eq!(
            images(&big, None, "").unwrap_err(),
            VerifiedBootError::KernelTooLarge(VERIFIED_KERNEL_MAX_BYTES + 1)
        );
        assert!(images(&big[..VERIFIED_KERNEL_MAX_BYTES], None, "").is_ok());
        let big = vec![0u8; VERIFIED_INITRD_MAX_BYTES + 1];
        assert_eq!(
            images(b"k", Some(&big), "").unwrap_err(),
            VerifiedBootError::InitrdTooLarge(VERIFIED_INITRD_MAX_BYTES + 1)
        );
        assert!(images(b"k", Some(&big[..VERIFIED_INITRD_MAX_BYTES]), "").is_ok());
    }

    #[test]
    fn verified_cmdline_syntax_and_length() {
        for bad in ["a\0b", "tab\there", "nl\n", "é"] {
            assert_eq!(
                images(b"k", None, bad).unwrap_err(),
                VerifiedBootError::CmdlineInvalid
            );
        }
        let max = VERIFIED_CMDLINE_MAX_BYTES.min(arch::CMDLINE_MAX_SIZE - 1);
        assert!(images(b"k", None, &"a".repeat(max)).is_ok());
        assert_eq!(
            images(b"k", None, &"a".repeat(max + 1)).unwrap_err(),
            VerifiedBootError::CmdlineTooLong(max + 1, max)
        );
    }

    #[test]
    fn verified_pin_syntax() {
        let c = sha(b"");
        let upper = ABC_SHA256.to_uppercase();
        let short = &ABC_SHA256[..63];
        let nonhex = format!("{}g", &ABC_SHA256[..63]);
        let long = format!("{ABC_SHA256}0");
        for bad in [upper.as_str(), short, nonhex.as_str(), long.as_str(), ""] {
            let pins = VerifiedBootPins {
                kernel_sha256: bad,
                initrd_sha256: None,
                cmdline_sha256: &c,
            };
            assert_eq!(
                VerifiedBootImages::new(b"abc", None, "", &pins).unwrap_err(),
                VerifiedBootError::PinSyntax("kernel")
            );
        }
    }
}
