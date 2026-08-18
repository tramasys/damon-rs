use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::error::io_error;
use crate::{AddressUnit, Error, MonitoringIntervals, Pid, RegionBounds};

use super::sysfs_io::*;
use super::*;

mod backend;
mod capabilities;
mod configuration;
#[path = "io.rs"]
mod io_tests;

#[derive(Default)]
struct RecordingWriter {
    calls: usize,
    bytes: Vec<u8>,
}

impl Write for RecordingWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.calls += 1;
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Default)]
struct InterruptedWriter {
    calls: usize,
    bytes: Vec<u8>,
}

impl Write for InterruptedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.calls += 1;
        if self.calls == 1 {
            return Err(io::ErrorKind::Interrupted.into());
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct ShortWriter;

impl Write for ShortWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        Ok(bytes.len().saturating_sub(1))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct TempFile {
    path: PathBuf,
}

impl TempFile {
    fn new(contents: &str) -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);

        let path = std::env::temp_dir().join(format!(
            "damon-rs-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&path, contents).expect("create temporary test file");
        Self { path }
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}
