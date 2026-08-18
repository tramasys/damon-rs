use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::error::io_error;
use crate::{Error, Result};

#[cfg(test)]
use super::test_backend;

pub(super) fn path_exists(path: &Path) -> Result<bool> {
    #[cfg(test)]
    if let Some(result) = test_backend::path_exists(path) {
        return result.map_err(|error| io_error("inspect", path, error));
    }
    path.try_exists()
        .map_err(|error| io_error("inspect", path, error))
}

pub(super) fn path_is_dir(path: &Path) -> Result<bool> {
    #[cfg(test)]
    if let Some(result) = test_backend::path_is_dir(path) {
        return result.map_err(|error| io_error("inspect", path, error));
    }
    match path.metadata() {
        Ok(metadata) => Ok(metadata.is_dir()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(io_error("inspect", path, error)),
    }
}

pub(super) fn numeric_directory_indices_into(path: &Path, indices: &mut Vec<usize>) -> Result<()> {
    indices.clear();
    #[cfg(test)]
    if let Some(result) = test_backend::numeric_directories(path) {
        let directories = result.map_err(|error| io_error("list directory", path, error))?;
        indices.extend(directories.into_iter().map(|(index, _)| index));
        return Ok(());
    }

    let entries = match std::fs::read_dir(path) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(io_error("list directory", path, error)),
    };
    for entry in entries {
        let entry = entry.map_err(|error| io_error("read directory entry", path, error))?;
        if !entry
            .file_type()
            .map_err(|error| io_error("inspect directory entry", entry.path(), error))?
            .is_dir()
        {
            continue;
        }
        let Some(index) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<usize>().ok())
        else {
            continue;
        };
        indices.push(index);
    }
    indices.sort_unstable();
    Ok(())
}

pub(super) fn all_files_recursive(root: &Path) -> Result<Vec<PathBuf>> {
    #[cfg(test)]
    if let Some(result) = test_backend::all_files_recursive(root) {
        return result.map_err(|error| io_error("walk hierarchy", root, error));
    }

    let mut files = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let entries = std::fs::read_dir(&directory)
            .map_err(|error| io_error("list directory", &directory, error))?;
        for entry in entries {
            let entry =
                entry.map_err(|error| io_error("read directory entry", &directory, error))?;
            let file_type = entry
                .file_type()
                .map_err(|error| io_error("inspect directory entry", entry.path(), error))?;
            if file_type.is_dir() {
                pending.push(entry.path());
            } else if file_type.is_file() {
                files.push(entry.path());
            }
        }
    }
    Ok(files)
}

pub(super) fn path_is_writable(path: &Path) -> Result<bool> {
    #[cfg(test)]
    if let Some(result) = test_backend::path_is_writable(path) {
        return result.map_err(|error| io_error("inspect permissions", path, error));
    }
    path.metadata()
        .map(|metadata| !metadata.permissions().readonly())
        .map_err(|error| io_error("inspect permissions", path, error))
}

pub(super) fn read_text(path: &Path) -> Result<String> {
    #[cfg(test)]
    if let Some(result) = test_backend::read(path) {
        let bytes = result.map_err(|error| io_error("read", path, error))?;
        return String::from_utf8(bytes)
            .map_err(|_| invalid_kernel_value(path, "<non-UTF-8 value>", "UTF-8 text"));
    }
    std::fs::read_to_string(path).map_err(|error| io_error("read", path, error))
}

pub(super) fn read_configuration_value_equals(path: &Path, expected: &[u8]) -> Result<bool> {
    #[cfg(test)]
    if let Some(result) = test_backend::read(path) {
        return match result {
            Ok(bytes) => Ok(configuration_bytes_equal(&bytes, expected)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(io_error("read", path, error)),
        };
    }

    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(io_error("open for reading", path, error)),
    };
    let mut matched = 0;
    let mut newline_seen = false;
    let mut bytes = [0_u8; 256];
    loop {
        let read = file
            .read(&mut bytes)
            .map_err(|error| io_error("read", path, error))?;
        if read == 0 {
            break;
        }
        if !match_configuration_chunk(&bytes[..read], expected, &mut matched, &mut newline_seen) {
            return Ok(false);
        }
    }
    Ok(matched == expected.len())
}

#[cfg(test)]
pub(super) fn configuration_bytes_equal(bytes: &[u8], expected: &[u8]) -> bool {
    let mut matched = 0;
    let mut newline_seen = false;
    match_configuration_chunk(bytes, expected, &mut matched, &mut newline_seen)
        && matched == expected.len()
}

pub(super) fn match_configuration_chunk(
    bytes: &[u8],
    expected: &[u8],
    matched: &mut usize,
    newline_seen: &mut bool,
) -> bool {
    for &byte in bytes {
        if *matched < expected.len() {
            if byte != expected[*matched] {
                return false;
            }
            *matched += 1;
        } else {
            if *newline_seen || byte != b'\n' {
                return false;
            }
            *newline_seen = true;
        }
    }
    true
}

pub(super) fn read_usize(path: &Path) -> Result<usize> {
    let value = read_u64(path)?;
    usize::try_from(value).map_err(|_| invalid_kernel_value(path, value.to_string(), "usize"))
}

pub(super) fn read_u32(path: &Path) -> Result<u32> {
    let value = read_u64(path)?;
    u32::try_from(value).map_err(|_| invalid_kernel_value(path, value.to_string(), "u32"))
}

pub(super) fn read_u8(path: &Path) -> Result<u8> {
    let value = read_u64(path)?;
    u8::try_from(value).map_err(|_| invalid_kernel_value(path, value.to_string(), "u8"))
}

pub(super) fn read_i32(path: &Path) -> Result<i32> {
    let value = read_text(path)?;
    let value = value.trim();
    value
        .parse()
        .map_err(|_| invalid_kernel_value(path, value, "i32"))
}

pub(super) fn read_bool(path: &Path) -> Result<bool> {
    let value = read_text(path)?;
    let value = value.trim();
    match value {
        "1" | "Y" | "y" | "yes" | "true" | "on" => Ok(true),
        "0" | "N" | "n" | "no" | "false" | "off" => Ok(false),
        _ => Err(invalid_kernel_value(path, value, "a Linux boolean")),
    }
}

pub(super) fn read_u64(path: &Path) -> Result<u64> {
    #[cfg(test)]
    if let Some(result) = test_backend::read(path) {
        let bytes = result.map_err(|error| io_error("read", path, error))?;
        if bytes.len() > 64 {
            return Err(invalid_kernel_value(path, "<value too long>", "u64"));
        }
        let value = std::str::from_utf8(&bytes)
            .map_err(|_| invalid_kernel_value(path, "<non-UTF-8 value>", "u64"))?
            .trim();
        return value
            .parse()
            .map_err(|_| invalid_kernel_value(path, value, "u64"));
    }
    let mut file = File::open(path).map_err(|error| io_error("open for reading", path, error))?;
    let mut bytes = [0_u8; 64];
    let mut used = 0;

    loop {
        if used == bytes.len() {
            return Err(invalid_kernel_value(path, "<value too long>", "u64"));
        }
        let read = file
            .read(&mut bytes[used..])
            .map_err(|error| io_error("read", path, error))?;
        if read == 0 {
            break;
        }
        used += read;
    }

    let value = std::str::from_utf8(&bytes[..used])
        .map_err(|_| invalid_kernel_value(path, "<non-UTF-8 value>", "u64"))?
        .trim();
    value
        .parse()
        .map_err(|_| invalid_kernel_value(path, value, "u64"))
}

pub(super) fn invalid_kernel_value(
    path: &Path,
    value: impl Into<Box<str>>,
    expected: &'static str,
) -> Error {
    Error::InvalidKernelValue {
        path: path.to_path_buf(),
        value: value.into(),
        expected,
    }
}

pub(super) fn duration_micros(duration: Duration) -> Result<u64> {
    let micros = u64::try_from(duration.as_micros()).map_err(|_| Error::InvalidConfiguration {
        field: "apply interval",
        reason: "does not fit in 64-bit microseconds",
    })?;
    if Duration::from_micros(micros) != duration {
        return Err(Error::InvalidConfiguration {
            field: "apply interval",
            reason: "must be exactly representable in whole microseconds",
        });
    }
    Ok(micros)
}

pub(super) fn duration_millis(duration: Duration) -> Result<u32> {
    let milliseconds =
        u32::try_from(duration.as_millis()).map_err(|_| Error::InvalidConfiguration {
            field: "refresh interval",
            reason: "does not fit in the kernel unsigned-int range",
        })?;
    if Duration::from_millis(u64::from(milliseconds)) != duration {
        return Err(Error::InvalidConfiguration {
            field: "refresh interval",
            reason: "must be exactly representable in whole milliseconds",
        });
    }
    Ok(milliseconds)
}

pub(super) fn write_value(path: &Path, value: impl fmt::Display) -> Result<()> {
    write_bytes(path, value.to_string().as_bytes())
}

pub(super) fn write_value_if_present(path: &Path, value: impl fmt::Display) -> Result<bool> {
    if !path_exists(path)? {
        return Ok(false);
    }
    write_value(path, value)?;
    Ok(true)
}

pub(super) fn write_bool(path: &Path, value: bool) -> Result<()> {
    write_bytes(path, if value { b"Y" } else { b"N" })
}

pub(super) fn write_bytes(path: &Path, value: &[u8]) -> Result<()> {
    #[cfg(test)]
    if let Some(result) = test_backend::write(path, value) {
        return result.map_err(|error| io_error("write", path, error));
    }
    let mut file = open_for_write(path)?;
    write_once(&mut file, path, value)
}

pub(super) fn write_once(writer: &mut impl Write, path: &Path, value: &[u8]) -> Result<()> {
    let written = loop {
        match writer.write(value) {
            Ok(written) => break written,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(io_error("write", path, error)),
        }
    };
    if written != value.len() {
        return Err(io_error(
            "write complete value",
            path,
            io::Error::new(
                io::ErrorKind::WriteZero,
                format!(
                    "short sysfs write: wrote {written} of {} bytes",
                    value.len()
                ),
            ),
        ));
    }
    Ok(())
}

pub(super) fn open_for_write(path: &Path) -> Result<File> {
    OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)
        .map_err(|error| io_error("open for writing", path, error))
}
